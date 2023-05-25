package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/registry-adapter/config"
	log "github.com/sirupsen/logrus"
)

const internalCertDir = "/etc/neuvector/certs/internal/"

const internalCACert string = "ca.cert"
const internalCert string = "cert.pem"
const internalCertKey string = "cert.key"
const internalCertCN string = "NeuVector"

const scanReportURL = "/endpoint/api/v1/scan/"
const scanEndpoint = "/endpoint/api/v1/scan"
const metadataEndpoint = "/endpoint/api/v1/metadata"

const reportSuffixURL = "/report"
const refreshInterval = 60
const dataCheckInterval = 1.0
const scannerCheckInterval = 5.0
const repoScanTimeout = time.Minute * 20

var rpcTimeout = 1000
var workloadID Counter
var concurrentJobs Counter
var expirationTime int64
var pruneTime int64
var rpcclient share.ControllerScanAdapterServiceClient

var serverConfig config.ServerConfig

var MimeOCI = "application/vnd.oci.image.manifest.v1+json"
var MimeDockerIM = "application/vnd.docker.distribution.manifest.v2+json"
var MimeSecurityVulnReport = "application/vnd.security.vulnerability.report; version=1.1"
var nvScanner = ScannerSpec{
	Name:    "neuvector",
	Vendor:  "neuvector_vendor",
	Version: "33.5",
}

var reportCache = ReportData{ScanReports: make(map[string]ScanReport)}
var queueMap = QueueMap{Entries: make(map[int]ScanRequest)}

func InitializeServer(config config.ServerConfig) {
	serverConfig = config
	log.SetLevel(log.DebugLevel)
	expirationTime = serverConfig.ExpirationTime
	pruneTime = serverConfig.PruneTime
	workloadID = Counter{count: 1}
	concurrentJobs = Counter{count: 0}
	go processQueueMap()
	go pruneOldEntries()
	defer http.DefaultClient.CloseIdleConnections()
	GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	http.HandleFunc("/", unhandled)
	http.HandleFunc(metadataEndpoint, authenticateHarbor(metadata))
	http.HandleFunc(scanEndpoint, authenticateHarbor(scan))
	http.HandleFunc(scanReportURL, authenticateHarbor(scanResult))
	log.WithFields(log.Fields{}).Debug("Server Started")
	http.ListenAndServe("0.0.0.0:8090", nil)
}

func unhandled(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		log.WithFields(log.Fields{"endpoint": req.URL}).Warning("Unhandled HTTP Endpoint")
		return
	}
}

func authenticateHarbor(function http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch authType := strings.ToLower(serverConfig.Auth.AuthorizationType); authType {
		case "basic":
			incUserName, incPass, ok := r.BasicAuth()
			if ok {
				username := os.Getenv(serverConfig.Auth.UsernameVaribale)
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

func metadata(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	log.WithFields(log.Fields{"request": req}).Info("Metadata request received")
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

func scan(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	scanRequest := ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("json unmarshal error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	scanRequest.Authorization = req.Header.Get("Authorization")

	log.WithFields(log.Fields{"auth": scanRequest.Authorization, "registry": scanRequest.Registry, "artifact": scanRequest.Artifact}).Debug("Scan request received")
	//Add to resultmap with wait http code
	w.WriteHeader(http.StatusAccepted)

	workloadID.Lock()
	queueMap.Lock()
	scanId := ScanRequestReturn{ID: fmt.Sprintf("%v", workloadID.GetNoLock())}
	scanRequest.WorkloadID = scanId.ID
	queueMap.Entries[workloadID.GetNoLock()] = scanRequest
	workloadID.Increment()
	queueMap.Unlock()
	workloadID.Unlock()

	reportCache.Lock()
	reportCache.ScanReports[scanId.ID] = ScanReport{Status: http.StatusFound, ExpirationTime: generateExpirationTime()}
	reportCache.Unlock()

	err = json.NewEncoder(w).Encode(scanId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.WithFields(log.Fields{"error": err}).Error("json encoder error")
		return
	}
	log.WithFields(log.Fields{}).Debug("End of scan request.")
}

func processQueueMap() {
	currentJob := 1
	for {
		time.Sleep(time.Second * time.Duration(dataCheckInterval))

		queueMap.Lock()
		job, ok := queueMap.Entries[currentJob]
		if ok {
			concurrentJobs.Lock()
			availableScanners, err := pollMaxConcurrent()
			if err != nil {
				queueMap.Unlock()
				concurrentJobs.Unlock()
				log.WithFields(log.Fields{"error": err}).Error("Error retrieving available scanners")
				continue
			}
			if uint32(concurrentJobs.GetNoLock()) <= availableScanners {
				go processScanTask(job)
				concurrentJobs.Increment()
				delete(queueMap.Entries, currentJob)
				queueMap.Unlock()
				currentJob++
			} else {
				queueMap.Unlock()
				time.Sleep(time.Second * 30)
			}
			concurrentJobs.Unlock()
		} else {
			queueMap.Unlock()
		}
	}
}

func processScanTask(scanRequest ScanRequest) {
	client, err := GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error retrieving rpc client")
		return
	}
	request := share.AdapterScanImageRequest{
		Registry:   scanRequest.Registry.URL,
		Repository: scanRequest.Artifact.Repository,
		Tag:        scanRequest.Artifact.Tag,
		Token:      scanRequest.Registry.Authorization,
		ScanLayers: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), repoScanTimeout)
	defer cancel()
	result, err := client.ScanImage(ctx, &request)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error sending scan request")
		return
	}
	concurrentJobs.Decrement()

	reportCache.Lock()
	reportCache.ScanReports[scanRequest.WorkloadID] = convertRPCReportToScanReport(result)
	reportCache.Unlock()
}

func convertRPCReportToScanReport(scanResult *share.ScanResult) ScanReport {
	var result ScanReport
	//TODO: Finish conversion/translation of Results
	result.Status = http.StatusOK
	result.Vulnerabilities = convertVulns(scanResult.Vuls)
	return result
}

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

func pollMaxConcurrent() (uint32, error) {
	client, err := GetControllerServiceClient(serverConfig.ControllerIP, serverConfig.ControllerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error retrieving rpc client")
		return 0, err
	}

	scanners, err := client.GetScanners(context.Background(), &share.RPCVoid{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error retrieving scanners from controller")
		return 0, err
	}
	log.WithFields(log.Fields{"scanners": scanners.Scanners, "idle scanners": scanners.IdleScanners, "max scanners available": scanners.MaxScanners}).Debug("Scanners reported")
	return scanners.MaxScanners, nil
}

func generateExpirationTime() time.Time {
	now := time.Now().UTC()
	result := now.Add(time.Minute * time.Duration(expirationTime))
	return result
}

func pruneOldEntries() {
	for {
		time.Sleep(time.Duration(pruneTime) * time.Minute)
		reportCache.Lock()
		for key, value := range reportCache.ScanReports {
			if value.ExpirationTime.Before(time.Now()) {
				delete(reportCache.ScanReports, key)
				log.WithFields(log.Fields{"key": key, "expires": value.ExpirationTime, "now": time.Now()}).Debug("Deleted entry due to expiration time")
			}
		}
		reportCache.Unlock()
	}
}

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

func scanResult(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	id := getIDFromReportRequest(req.URL.String())
	id = strings.Split(id, "/")[0]
	reportCache.Lock()
	if val, ok := reportCache.ScanReports[id]; ok {
		log.WithFields(log.Fields{"id": id}).Debug("Entry found for scan report")
		switch status := reportCache.ScanReports[id].Status; status {
		case http.StatusFound:
			log.WithFields(log.Fields{"id": id}).Debug("Result not found for scan report")
			w.Header().Add("Location", req.URL.String())
			w.Header().Add("Refresh-After", "60")
			w.WriteHeader(http.StatusFound)
		case http.StatusOK:
			err := json.NewEncoder(w).Encode(val)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("json encoder error")
				w.WriteHeader(http.StatusInternalServerError)
			}
		default:
			w.Header().Add("Location", req.URL.String())
			w.WriteHeader(val.Status)
		}
	} else {
		log.WithFields(log.Fields{"id": id}).Debug("Result not found for scan report (2)")
		w.Header().Add("Location", req.URL.String())
		w.Header().Add("Refresh-After", "60")
		w.WriteHeader(302)
	}
	reportCache.Unlock()
}

func getIDFromReportRequest(fullURL string) string {
	splitURL := strings.Split(fullURL, scanReportURL)
	result := splitURL[len(splitURL)-1]
	result = strings.Replace(result, reportSuffixURL, "", 1)
	return result
}
