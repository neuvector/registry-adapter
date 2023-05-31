package config

import (
	"io/ioutil"
	"os"
	"strconv"

	"gopkg.in/yaml.v2"
)

const AUTH_BASIC = "basic"
const AUTH_APIKEY = "api"
const AUTH_TOKEN = "token"

type ServerConfig struct {
	Auth                   Authorization `yaml:"Authorization"`
	ControllerIPVariable   string        `yaml:"ControllerIPVariable"`
	ControllerPortVariable string        `yaml:"ControllerPortVariable"`
	ControllerIP           string
	ControllerPort         uint16
}

type Authorization struct {
	AuthorizationType string `yaml:"AuthorizationType"`
	UsernameVaribale  string `yaml:"UsernameVariable"`
	PasswordVariable  string `yaml:"PasswordVariable"`
}

//readYAML reads in the external YAML config file.
func ReadYAML(path string) (*ServerConfig, error) {
	config := &ServerConfig{}
	configFile, err := ioutil.ReadFile(path)
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
	serverConfig.ControllerIP = os.Getenv(serverConfig.ControllerIPVariable)
	port, err := strconv.ParseUint(os.Getenv(serverConfig.ControllerPortVariable), 10, 16)
	port16 := uint16(port)
	if err != nil {
		return err
	}
	serverConfig.ControllerPort = port16
	return nil
}
