package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: scan [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "SAP"})

	join := flag.String("j", "", "Controller join address")
	joinPort := flag.Uint("join_port", 0, "Controller join port")

	flag.Usage = usage
	flag.Parse()

	if *joinPort == 0 {
		port := (uint)(api.DefaultControllerRESTAPIPort)
		joinPort = &port
	}

	getControllerServiceClient(*join, (uint16)(*joinPort))
}
