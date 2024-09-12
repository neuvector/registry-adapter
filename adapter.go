package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/healthz"
	"github.com/neuvector/neuvector/share/migration"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/registry-adapter/config"
	"github.com/neuvector/registry-adapter/server"
)

const repoScanTimeout = time.Minute * 20

func usage() {
	fmt.Fprintf(os.Stderr, "usage: scan [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "SAP"})

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// when run in container, values are read from the environment variables
	proto := flag.String("proto", "https", "Server protocol")
	join := flag.String("j", "", "Controller join address")
	joinPort := flag.Uint("join_port", 0, "Controller join port")

	image := flag.String("image", "", "Test image path")
	token := flag.String("token", "", "Test image token")

	flag.Usage = usage
	flag.Parse()

	// Reload internal certs

	var internalCertControllerCancel context.CancelFunc
	var ctx context.Context
	var err error

	if os.Getenv("AUTO_INTERNAL_CERT") != "" {

		log.Info("start initializing k8s internal secret controller and wait for internal secret creation if it's not created")

		go func() {
			if err := healthz.StartHealthzServer(); err != nil {
				log.WithError(err).Warn("failed to start healthz server")
			}
		}()

		ctx, internalCertControllerCancel = context.WithCancel(context.Background())
		defer internalCertControllerCancel()
		// Initialize secrets.  Most of services are not running at this moment, so skip their reload functions.
		capable, err := migration.InitializeInternalSecretController(ctx, []func([]byte, []byte, []byte) error{
			// Reload grpc client
			func(cacert []byte, cert []byte, key []byte) error {
				log.Info("Reloading gRPC servers/clients")
				if err := cluster.ReloadInternalCert(); err != nil {
					return fmt.Errorf("failed to reload gRPC's certificate: %w", err)
				}
				return nil
			},
		})
		if err != nil {
			log.WithError(err).Error("failed to initialize internal secret controller")
			os.Exit(-2)
		}
		if capable {
			log.Info("internal certificate is initialized")
		} else {
			if os.Getenv("NO_FALLBACK") == "" {
				log.Warn("required permission is missing...fallback to the built-in certificate if it exists")
			} else {
				log.Error("required permission is missing...ending now")
				os.Exit(-2)
			}
		}
	}
	err = cluster.ReloadInternalCert()
	if err != nil {
		log.WithError(err).Fatal("failed to reload internal certificate")
	}

	if *joinPort == 0 {
		port := (uint)(cluster.DefaultControllerGRPCPort)
		joinPort = &port
	}

	if *image != "" {
		testImageScan(*join, *joinPort, *image, *token)
		return
	}

	var serverConfig config.ServerConfig

	if *join != "" {
		serverConfig.ControllerIP = *join
		serverConfig.ControllerPort = uint16(*joinPort)
		serverConfig.ServerProto = *proto
		serverConfig.Auth.AuthorizationType = config.AUTH_BASIC
		serverConfig.Auth.UsernameVariable = config.EnvHarborAuthUsername
		serverConfig.Auth.PasswordVariable = config.EnvHarborAuthPassword
	} else {
		err := serverConfig.LoadEnvironementVariables()
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error retrieving controller port")
			return
		}
	}

	server.InitializeServer(&serverConfig)
}

func testImageScan(join string, joinPort uint, image, token string) {
	reg, repo, tag, err := scanUtils.ParseImageName(image)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed parse the image path")
		return
	}

	req := &share.AdapterScanImageRequest{
		Registry:   reg,
		Repository: repo,
		Tag:        tag,
		Token:      token,
	}

	log.WithFields(log.Fields{"request": req}).Debug("Scan image request")

	ctx, cancel := context.WithTimeout(context.Background(), repoScanTimeout)
	defer cancel()

	client, err := server.GetControllerServiceClient(join, (uint16)(joinPort))
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to initiate grpc call")
		return
	}

	result, err := client.ScanImage(ctx, req)

	if result == nil {
		log.WithFields(log.Fields{"error": err}).Error("RPC request fail")
	} else if result.Error != share.ScanErrorCode_ScanErrNone {
		log.WithFields(log.Fields{"error": scanUtils.ScanErrorToStr(result.Error)}).Error("Failed to scan repository")
	} else {
		log.WithFields(log.Fields{"vulns": len(result.Vuls)}).Info("Scan repository finish")
	}
}
