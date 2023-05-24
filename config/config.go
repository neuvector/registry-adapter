package config

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

const AUTH_BASIC = "basic"
const AUTH_APIKEY = "api"
const AUTH_TOKEN = "token"

type ServerConfig struct {
	Auth           Authorization `yaml:"Authorization"`
	ControllerIP   string        `yaml:"ControllerIP"`
	ControllerPort uint16        `yaml:"ControllerPort"`
	ExpirationTime int64         `yaml:"ExpirationTime"`
	PruneTime      int64         `yaml:"PruneTime"`
}

type Authorization struct {
	AuthorizationType string `yaml:"AuthorizationType"`
	UsernameVaribale  string `yaml:"UsernameVariable"`
	PasswordVariable  string `yaml:"PasswordVariable"`
}

//readYAML reads in the external YAML config file.
func ReadYAML(path string) ServerConfig {
	config := ServerConfig{}
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("config file read error: %v\n", err)
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalf("failed to unmarshal yaml file: %v\n", err)
	}
	return config
}

func LoadEnvVariables() {

}
