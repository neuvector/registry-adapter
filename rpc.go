package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

const controller string = "controller"

func createControllerScanAdapterServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerScanServiceClient(conn)
}

func getControllerServiceClient(joinIP string, joinPort uint16) (share.ControllerScanAdapterServiceClient, error) {
	if cluster.GetGRPCClientEndpoint(controller) == "" {
		ep := fmt.Sprintf("%s:%v", joinIP, joinPort)
		cluster.CreateGRPCClient(controller, ep, true, createControllerScanAdapterServiceWrapper)
	}
	c, err := cluster.GetGRPCClient(controller, nil, nil)
	if err == nil {
		return c.(share.ControllerScanAdapterServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}
