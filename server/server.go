package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/registry-adapter/config"
	log "github.com/sirupsen/logrus"
)

const scanReportURL = "/endpoint/api/v1/scan/"
const scanEndpoint = "/endpoint/api/v1/scan"
const metadataEndpoint = "/endpoint/api/v1/metadata"
const adapterHttpsPort = "9443"
const adapterHttpPort = "8090"
const certFile = "/etc/neuvector/certs/ssl-cert.pem"
const keyFile = "/etc/neuvector/certs/ssl-cert.key"

const reportSuffixURL = "/report"
const dataCheckInterval = 1.0

const rpcTimeout = time.Minute * 20
const expirationTime = time.Minute * 25
const pruneTime = time.Minute * 60

var workloadID Counter
var concurrentJobs Counter

var serverConfig config.ServerConfig

var MimeOCI = "application/vnd.oci.image.manifest.v1+json"
var MimeDockerIM = "application/vnd.docker.distribution.manifest.v2+json"
var MimeSecurityVulnReport = "application/vnd.security.vulnerability.report; version=1.1"
var nvScanner = ScannerSpec{
	Name:    "NeuVector",
	Vendor:  "NeuVector",
	Version: "",
}

var reportCache = ReportData{ScanReports: make(map[string]ScanReport)}
var scanRequestQueue = ScanRequestQueue{}

//InitializeServer sets up the go routines and http handlers to handle requests from Harbor.
func InitializeServer(config *config.ServerConfig) {
	serverConfig = *config
	log.SetLevel(log.DebugLevel)
	workloadID = Counter{count: 1}
	concurrentJobs = Counter{count: 0}
	defer http.DefaultClient.CloseIdleConnections()
	_, err := GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error establishing grpc connection to controller")
		return
	}
	for nvScanner.Version == "" {
		time.Sleep(time.Second * 3)
		pollMaxConcurrent()
	}
	http.HandleFunc("/", unhandled)
	http.HandleFunc(metadataEndpoint, authenticateHarbor(metadata))
	http.HandleFunc(scanEndpoint, authenticateHarbor(scan))
	http.HandleFunc(scanReportURL, authenticateHarbor(scanResult))
	go processQueue()
	go pruneOldEntries()

	for {
		var err error
		if serverConfig.ServerProto == "https" {
			log.Debug("Start https")

			tlsconfig := &tls.Config{
				MinVersion:               tls.VersionTLS11,
				PreferServerCipherSuites: true,
				CipherSuites:             utils.GetSupportedTLSCipherSuites(),
			}
			server := &http.Server{
				Addr:      fmt.Sprintf(":%s", adapterHttpsPort),
				TLSConfig: tlsconfig,
				// ReadTimeout:  time.Duration(5) * time.Second,
				// WriteTimeout: time.Duration(35) * time.Second,
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0), // disable http/2
			}
			err = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			log.Debug("Start http")
			err = http.ListenAndServe(fmt.Sprintf(":%s", adapterHttpPort), nil)
		}

		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error starting server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}
}

//unhandled is the default response for unhandled urls.
func unhandled(w http.ResponseWriter, req *http.Request) {
	log.WithFields(log.Fields{"URL": req.URL.String()}).Debug()
	defer req.Body.Close()

	http.NotFound(w, req)
	log.WithFields(log.Fields{"endpoint": req.URL}).Warning("Unhandled HTTP Endpoint")
}

//authenticateHarbor wraps other handlerfuncs with basic authentication.
func authenticateHarbor(function http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch authType := strings.ToLower(serverConfig.Auth.AuthorizationType); authType {
		case "basic":
			incUserName, incPass, ok := r.BasicAuth()
			if ok {
				username := os.Getenv(serverConfig.Auth.UsernameVariable)
				pass := os.Getenv(serverConfig.Auth.PasswordVariable)
				if incUserName == username && incPass == pass {
					log.Debug("Authentication successful")
					function.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Incorrect username or password", http.StatusUnauthorized)
				log.Warn("Incorrect username or password")
			}
		default:
			log.WithFields(log.Fields{"auth type": authType}).Error("Unsupported authentication type")
		}
	})
}

//metadata returns the basic metadata harbor requests regularly from the adapter.
func metadata(w http.ResponseWriter, req *http.Request) {
	log.WithFields(log.Fields{"URL": req.URL.String()}).Debug()
	defer req.Body.Close()

	properties := map[string]string{
		"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
	}
	metadata := ScannerAdapterMetadata{
		Scanner: nvScanner,
		Capabilities: []Capability{
			{
				ConsumeMIMEs: []string{
					MimeOCI,
					MimeDockerIM,
				},
				ProduceMIMEs: []string{
					MimeSecurityVulnReport,
				},
			},
		},
		Properties: properties,
	}
	mimeVer := map[string]string{"version": "1.0"}
	header := mimestring("application", "vnd.scanner.adapter.metadata+json", mimeVer)
	w.Header().Set("Content-Type", header)
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(metadata)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.WithFields(log.Fields{"error": err}).Error("json encoder error")
	}
}

//scan translates incoming requests into ScanRequest and queues them for processing.
func scan(w http.ResponseWriter, req *http.Request) {
	log.WithFields(log.Fields{"URL": req.URL.String()}).Debug()
	defer req.Body.Close()

	scanRequest := ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("json unmarshal error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	scanRequest.Authorization = req.Header.Get("Authorization")

	//Add to resultmap with wait http code
	w.WriteHeader(http.StatusAccepted)

	workloadID.Lock()
	scanRequestQueue.Lock()
	scanId := ScanRequestReturn{ID: fmt.Sprintf("%v", workloadID.GetNoLock())}
	scanRequest.WorkloadID = scanId.ID
	scanRequestQueue.Enqueue(scanRequest)
	log.WithFields(log.Fields{"workloadid": scanId, "auth": scanRequest.Authorization, "registry": scanRequest.Registry, "artifact": scanRequest.Artifact}).Debug("Scan request received")
	workloadID.Increment()
	scanRequestQueue.Unlock()
	workloadID.Unlock()

	reportCache.Lock()
	expirationTime := generateExpirationTime()
	ScanReport := ScanReport{Status: http.StatusFound, ExpirationTime: expirationTime}
	reportCache.ScanReports[scanId.ID] = ScanReport
	reportCache.Unlock()

	err = json.NewEncoder(w).Encode(scanId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.WithFields(log.Fields{"error": err}).Error("json encoder error")
		return
	}
	log.WithFields(log.Fields{}).Debug("End of scan request.")
}

//processQueue goes through the queue in first-in-first-out order if concurrent jobs are less than the maximum allowed jobs.
func processQueue() {
	for {
		time.Sleep(time.Second * time.Duration(dataCheckInterval))

		scanRequestQueue.Lock()
		if scanRequestQueue.Length() > 0 {
			concurrentJobs.Lock()
			availableScanners, err := pollMaxConcurrent()
			if err != nil {
				scanRequestQueue.Unlock()
				concurrentJobs.Unlock()
				log.WithFields(log.Fields{"error": err}).Error("Error retrieving available scanners")
				continue
			}
			if uint32(concurrentJobs.GetNoLock()) <= availableScanners {
				job := scanRequestQueue.Dequeue()
				go processScanTask(job)
				concurrentJobs.Increment()
				scanRequestQueue.Unlock()
			} else {
				scanRequestQueue.Unlock()
				time.Sleep(time.Second * 30)
			}
			concurrentJobs.Unlock()
		} else {
			scanRequestQueue.Unlock()
		}
	}
}

//processScanTask sends the ScanRequest to the controller, which creates tasks for the attached scanners.
//Afterwards, the result is added to the saved scan reports.
func processScanTask(scanRequest ScanRequest) {
	client, err := GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	if err != nil {
		reportCache.Lock()
		report := reportCache.ScanReports[scanRequest.WorkloadID]
		report.Status = http.StatusInternalServerError
		reportCache.ScanReports[scanRequest.WorkloadID] = report
		reportCache.Unlock()
		log.WithFields(log.Fields{"error": err}).Error("Error establishing grpc connection to controller")
		concurrentJobs.Decrement()
		return
	}
	request := share.AdapterScanImageRequest{
		Registry:   scanRequest.Registry.URL,
		Repository: scanRequest.Artifact.Repository,
		Tag:        scanRequest.Artifact.Tag,
		Token:      scanRequest.Registry.Authorization,
		ScanLayers: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	log.WithFields(log.Fields{"workloadId": scanRequest.WorkloadID, "artifact": scanRequest.Artifact, "registry": scanRequest.Registry}).Debug("Scan request forwarded to controller")
	result, err := client.ScanImage(ctx, &request)
	if err != nil {
		reportCache.Lock()
		report := reportCache.ScanReports[scanRequest.WorkloadID]
		report.Status = http.StatusInternalServerError
		reportCache.ScanReports[scanRequest.WorkloadID] = report
		reportCache.Unlock()
		log.WithFields(log.Fields{"error": err}).Error("Error sending scan request")
		concurrentJobs.Decrement()
		return
	}
	concurrentJobs.Decrement()
	reportCache.Lock()
	reportCache.ScanReports[scanRequest.WorkloadID] = convertRPCReportToScanReport(result)
	reportCache.Unlock()
}

//convertRPCReportToScanReport converts the rpc results from the controller into a Harbor readable format.
func convertRPCReportToScanReport(scanResult *share.ScanResult) ScanReport {
	var result ScanReport
	result.Status = http.StatusOK
	result.Vulnerabilities = convertVulns(scanResult.Vuls)
	return result
}

//convertVulns changes the controller vuln results into a Harbor readable format.
func convertVulns(controllerVulns []*share.ScanVulnerability) []Vuln {
	translatedVulns := make([]Vuln, len(controllerVulns))
	for index, rawVuln := range controllerVulns {
		translatedVuln := Vuln{
			ID:          rawVuln.Name,
			Pkg:         rawVuln.PackageName,
			Version:     rawVuln.PackageVersion,
			FixVersion:  rawVuln.FixedVersion,
			Severity:    rawVuln.Severity,
			Description: rawVuln.Description,
			Links:       []string{rawVuln.Link},
			PreferredCVSS: &CVSSDetails{
				ScoreV2:  rawVuln.GetScore(),
				ScoreV3:  rawVuln.GetScoreV3(),
				VectorV2: rawVuln.GetVectors(),
				VectorV3: rawVuln.GetVectorsV3(),
			},
			CweIDs:           []string{},
			VendorAttributes: map[string]interface{}{},
		}
		translatedVulns[index] = translatedVuln
	}
	return translatedVulns
}

//pollMaxConcurrent finds the max amount of available scanners by polling the controller.
func pollMaxConcurrent() (uint32, error) {
	client, err := GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error establishing grpc connection to controller")
		return 0, err
	}

	scanners, err := client.GetScanners(context.Background(), &share.RPCVoid{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error retrieving scanners from controller")
		return 0, err
	}
	nvScanner.Version = scanners.ScannerVersion
	log.WithFields(log.Fields{"scanners": scanners.Scanners, "idle scanners": scanners.IdleScanners, "max scanners available": scanners.MaxScanners, "scanner version": nvScanner.Version}).Debug("Scanners reported")
	return scanners.MaxScanners, nil
}

//generateExpirationTime generates the timestamp that entries should be deleted after when they aren't retrieved.
func generateExpirationTime() time.Time {
	now := time.Now().UTC()
	result := now.Add(expirationTime)
	return result
}

//pruneOldEntries deletes entries that have passed their expiration timestamp.
func pruneOldEntries() {
	for {
		time.Sleep(pruneTime)
		reportCache.Lock()
		for key, value := range reportCache.ScanReports {
			if value.ExpirationTime.Before(time.Now()) {
				delete(reportCache.ScanReports, key)
				log.WithFields(log.Fields{"workloadid": key, "expires": value.ExpirationTime, "now": time.Now()}).Debug("Deleted entry due to expiration time")
			}
		}
		reportCache.Unlock()
	}
}

//mimestring generates the mimestring format
func mimestring(mimetype string, subtype string, inparams map[string]string) string {
	s := fmt.Sprintf("%s/%s", mimetype, subtype)
	if len(inparams) == 0 {
		return s
	}
	params := make([]string, 0, len(inparams))
	for k, v := range inparams {
		params = append(params, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s; %s", s, strings.Join(params, ";"))
}

//scanResult returns the scan report with the matching id when requested.
func scanResult(w http.ResponseWriter, req *http.Request) {
	log.WithFields(log.Fields{"URL": req.URL.String()}).Debug()
	defer req.Body.Close()

	id := getIDFromReportRequest(req.URL.String())
	id = strings.Split(id, "/")[0]
	reportCache.Lock()
	if val, ok := reportCache.ScanReports[id]; ok {
		log.WithFields(log.Fields{"id": id}).Debug("Entry found for scan report")
		switch status := reportCache.ScanReports[id].Status; status {
		case http.StatusFound:
			log.WithFields(log.Fields{"id": id}).Debug("Result not ready yet for scan report")
			w.Header().Add("Location", req.URL.String())
			w.Header().Add("Refresh-After", "60")
			w.WriteHeader(http.StatusFound)
		case http.StatusOK:
			err := json.NewEncoder(w).Encode(val)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("json encoder error")
				w.WriteHeader(http.StatusInternalServerError)
			}
			log.WithFields(log.Fields{"id": id}).Debug("Scan report sent to Harbor")
			delete(reportCache.ScanReports, id)
		case http.StatusInternalServerError:
			log.WithFields(log.Fields{"id": id}).Debug("returned http 500 for workload id")
			w.WriteHeader(http.StatusInternalServerError)
			delete(reportCache.ScanReports, id)
		default:
			w.Header().Add("Location", req.URL.String())
			w.WriteHeader(val.Status)
		}
	} else {
		w.Header().Add("Location", req.URL.String())
		log.WithFields(log.Fields{"id": id}).Debug("Entry not found for scan report")
		w.WriteHeader(http.StatusNotFound)
	}
	reportCache.Unlock()
}

//getIDFromReportRequest separates the report ID from the URL.
func getIDFromReportRequest(fullURL string) string {
	splitURL := strings.Split(fullURL, scanReportURL)
	result := splitURL[len(splitURL)-1]
	result = strings.Replace(result, reportSuffixURL, "", 1)
	return result
}
