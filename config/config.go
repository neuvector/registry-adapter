package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const AUTH_BASIC = "basic"
const AUTH_APIKEY = "api"
const AUTH_TOKEN = "token"

const EnvCtrlServerIP = "CLUSTER_JOIN_ADDR"
const EnvCtrlServerPort = "CLUSTER_JOIN_PORT"
const EnvHarborServerProto = "HARBOR_SERVER_PROTO"
const EnvHarborAuthUsername = "HARBOR_BASIC_AUTH_USERNAME"
const EnvHarborAuthPassword = "HARBOR_BASIC_AUTH_PASSWORD"
const EnvUseFeedBasedSeverity = "USE_FEED_BASED_SEVERITY"
const EnvScanLayers = "SCAN_LAYERS"
const EnvDequeueInterval = "SCAN_DEQUEUE_INTERVAL"
const EnvGateRetryDelay = "SCAN_GATE_RETRY_DELAY"

type ServerConfig struct {
	Auth                 Authorization `yaml:"Authorization"`
	ServerProto          string        `yaml:"ServerProto"`
	ControllerIP         string
	ControllerPort       uint16
	LogLevel             logrus.Level
	UseFeedBasedSeverity bool `yaml:"UseFeedBasedSeverity"`
	// ScanLayers requests per-layer vulnerability results from the controller.
	// It defaults to false (matching NeuVector's other scan paths); the adapter
	// only consumes the flat Vuls list, so enabling it only adds payload that is
	// discarded, unless the per-layer breakdown is wanted in NeuVector's own
	// stored repo-scan report.
	ScanLayers      bool `yaml:"ScanLayers"`
	DequeueInterval float64
	GateRetryDelay  time.Duration
}

type Authorization struct {
	AuthorizationType string `yaml:"AuthorizationType"`
	UsernameVariable  string `yaml:"UsernameVariable"`
	PasswordVariable  string `yaml:"PasswordVariable"`
}

// readYAML reads in the external YAML config file.
func ReadYAML(path string) (*ServerConfig, error) {
	config := &ServerConfig{}
	configFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (serverConfig *ServerConfig) LoadEnvironementVariables() error {
	serverConfig.ServerProto = os.Getenv(EnvHarborServerProto)
	serverConfig.ControllerIP = os.Getenv(EnvCtrlServerIP)
	if v, ok := os.LookupEnv(EnvCtrlServerPort); ok {
		port, err := strconv.ParseUint(v, 10, 16)
		port16 := uint16(port)
		if err != nil {
			return err
		}
		serverConfig.ControllerPort = port16
	} else {
		serverConfig.ControllerPort = cluster.DefaultControllerGRPCPort
	}

	serverConfig.Auth.AuthorizationType = AUTH_BASIC
	serverConfig.Auth.UsernameVariable = EnvHarborAuthUsername
	serverConfig.Auth.PasswordVariable = EnvHarborAuthPassword
	if v, ok := os.LookupEnv(EnvUseFeedBasedSeverity); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		serverConfig.UseFeedBasedSeverity = b
	}
	if v, ok := os.LookupEnv(EnvScanLayers); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		serverConfig.ScanLayers = b
	}

	serverConfig.DequeueInterval = 1.0
	if v, ok := os.LookupEnv(EnvDequeueInterval); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 {
			return fmt.Errorf("invalid %s: %s", EnvDequeueInterval, v)
		}
		serverConfig.DequeueInterval = f
	}

	serverConfig.GateRetryDelay = 5 * time.Second
	if v, ok := os.LookupEnv(EnvGateRetryDelay); ok {
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil || secs <= 0 {
			return fmt.Errorf("invalid %s: %s", EnvGateRetryDelay, v)
		}
		serverConfig.GateRetryDelay = time.Duration(secs * float64(time.Second))
	}

	return nil
}
