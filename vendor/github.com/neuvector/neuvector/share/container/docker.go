package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	dockerEvent "github.com/docker/docker/api/types/events"
	dockerImage "github.com/docker/docker/api/types/image"
	dockerNetwork "github.com/docker/docker/api/types/network"
	dockerSystem "github.com/docker/docker/api/types/system"
	dockerClient "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultDockerSocket string = "/var/run/docker.sock"
const defaultDockerShimSocket string = "/var/run/dockershim.sock"

type MsgEventCallback func(e dockerEvent.Message)

type dockerDriver struct {
	sys          *system.SystemTools
	endpoint     string
	endpointHost string
	selfID       string
	evCallback   EventCallback
	client       *dockerClient.Client
	version      *dockerTypes.Version
	info         *dockerSystem.Info
	rtProcMap    utils.Set
	pidHost      bool
	eventCancel  context.CancelFunc
}

func _connect(endpoint string) (*dockerClient.Client, *dockerTypes.Version, *dockerSystem.Info, error) {
	var ver dockerTypes.Version
	var info dockerSystem.Info

	if !strings.HasPrefix(endpoint, "unix://") {
		endpoint = "unix://" + endpoint
	}

	log.WithFields(log.Fields{"endpoint": endpoint}).Info("Connecting to docker")
	client, err := dockerClient.NewClientWithOpts(
		dockerClient.WithHost(endpoint),
		dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create client")
		return nil, nil, nil, err
	}

	if ver, err = client.ServerVersion(context.Background()); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get version")
		return client, nil, nil, err
	}

	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("docker connected")
	if info, err = client.Info(context.Background()); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get info")
		return client, &ver, nil, err
	}
	return client, &ver, &info, nil
}

func getContainerSocketPath(client *dockerClient.Client, id, endpoint string) (string, error) {
	if !IsPidHost() {
		return "", nil
	}
	if strings.HasPrefix(endpoint, "/proc/1/root") {
		return strings.TrimPrefix(endpoint, "/proc/1/root"), nil
	}

	info, err := client.ContainerInspect(context.Background(), id)
	if err == nil {
		endpoint = strings.TrimPrefix(endpoint, "unix://")
		for _, m := range info.Mounts {
			if m.Destination == endpoint {
				return m.Source, nil
			}
		}
	}
	log.WithFields(log.Fields{"error": err, "endpoint": endpoint}).Error("Failed to get mounting container socket")
	return "", err
}

func dockerConnect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	client, ver, info, err := _connect(endpoint)
	if err != nil {
		return nil, err
	}

	var sockPath string
	id, _, err := sys.GetSelfContainerID() // ref, not reliable
	if err != nil {
		log.WithFields(log.Fields{"err": err, "id": id}).Info()
	}
	sockPath, err = getContainerSocketPath(client, id, endpoint)
	if err == nil {
		log.WithFields(log.Fields{"selfID": id, "sockPath": sockPath}).Info()
	}

	driver := dockerDriver{sys: sys, endpoint: endpoint, endpointHost: sockPath, client: client,
		version: ver, info: info, selfID: id}
	driver.rtProcMap = utils.NewSet("runc", "docker-runc", "docker", "docker-runc-current",
		"docker-containerd-shim-current", "containerd-shim-runc-v1", "containerd-shim-runc-v2", "containerd", "containerd-shim")
	driver.pidHost = IsPidHost()
	return &driver, nil
}

func (d *dockerDriver) reConnect() error {
	if !d.pidHost {
		return errors.New("Not pidHost")
	}

	// the original socket has been recreated and its mounted path was also lost.
	endpoint := d.endpoint
	if d.endpointHost != "" { // use the host
		endpoint = filepath.Join("/proc/1/root", d.endpointHost)
		endpoint, _ = justifyRuntimeSocketFile(endpoint)
	}

	if d.client != nil {
		d.client.Close()
	}

	log.WithFields(log.Fields{"endpoint": endpoint}).Info("Reconnecting ...")
	client, ver, info, err := _connect(endpoint)
	if err != nil {
		return err
	}

	// update records
	d.client = client
	d.version = ver
	d.info = info
	return nil
}

func (d *dockerDriver) String() string {
	return RuntimeDocker
}

func (d *dockerDriver) GetHost() (*share.CLUSHost, error) {
	var host share.CLUSHost

	host.Runtime = d.String()
	if d.version != nil {
		host.RuntimeVer = d.version.Version
		host.RuntimeAPIVer = d.version.APIVersion
	}

	if d.info != nil {
		host.Name = d.info.Name
		host.ID = fmt.Sprintf("%s:%s", d.info.Name, d.info.ID)
		host.OS = d.info.OperatingSystem
		host.Kernel = d.info.KernelVersion
		host.CPUs = int64(d.info.NCPU)
		host.Memory = d.info.MemTotal
		host.StorageDriver = d.info.Driver
	}

	return &host, nil
}

func (d *dockerDriver) GetSelfID() string {
	return d.selfID
}

func (d *dockerDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	return getDevice(id, d, d.sys)
}

func (d *dockerDriver) ListContainerIDs() (utils.Set, utils.Set) {
	set := utils.NewSet()

	containers, err := d.client.ContainerList(context.Background(), dockerContainer.ListOptions{All: true})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in listing containers")
		return set, nil
	}

	for _, c := range containers {
		set.Add(c.ID)
	}
	return set, nil
}

func (d *dockerDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) {
	containers, err := d.client.ContainerList(context.Background(), dockerContainer.ListOptions{All: !runningOnly})
	if err != nil {
		log.WithFields(log.Fields{"error": err, "runningOnly": runningOnly}).Error("Fail to list containers")
		return nil, err
	}

	metas := make([]*ContainerMeta, len(containers))
	for i, c := range containers {
		metas[i] = &ContainerMeta{
			ID:     c.ID,
			Image:  d.getImageRepoTag("", c.Image), // c.Image,
			Labels: c.Labels,
		}
		if len(c.Names) > 0 {
			metas[i].Name = trimContainerName(c.Names[0])
		}
	}
	return metas, nil
}

func (d *dockerDriver) GetContainer(id string) (*ContainerMetaExtra, error) {
	info, err := d.client.ContainerInspect(context.Background(), id)
	if err != nil {
		return nil, err
	}

	meta := &ContainerMetaExtra{
		ContainerMeta: ContainerMeta{
			ID:       info.ID,
			Name:     trimContainerName(info.Name),
			Image:    d.getImageRepoTag(info.Image, info.Config.Image),
			Labels:   info.Config.Labels,
			Hostname: info.Config.Hostname,
			Pid:      info.State.Pid,
			Envs:     info.Config.Env,
			PidMode:  string(info.HostConfig.PidMode),
			NetMode:  string(info.HostConfig.NetworkMode),
		},
		ImageID:     TrimImageID(info.Image),
		Privileged:  info.HostConfig.Privileged,
		Running:     info.State.Running,
		ExitCode:    info.State.ExitCode,
		IPAddress:   info.NetworkSettings.IPAddress,
		IPPrefixLen: info.NetworkSettings.IPPrefixLen,
		MappedPorts: make(map[share.CLUSProtoPort]*share.CLUSMappedPort),
		Networks:    utils.NewSet(),
		LogPath:     info.LogPath,
	}

	if tm, err := time.Parse(time.RFC3339, info.State.StartedAt); err == nil {
		meta.StartedAt = tm
	}

	if tm, err := time.Parse(time.RFC3339, info.State.FinishedAt); err == nil {
		meta.FinishedAt = tm
	}

	if info.Config != nil && info.Config.Healthcheck != nil {
		// log.WithFields(log.Fields{"health": info.Config.Healthcheck}).Debug()
		meta.Healthcheck = make([]string, len(info.Config.Healthcheck.Test))
		copy(meta.Healthcheck, info.Config.Healthcheck.Test)
	}

	if info, err := d.client.ImageInspect(context.Background(), meta.ImageID); err == nil {
		meta.Author = info.Author
		if tm, err := time.Parse(time.RFC3339, info.Created); err == nil {
			meta.ImgCreateAt = tm
		}
	}

	meta.isChild, _ = d.GetParent(meta, nil)

	if tm, err := time.Parse(time.RFC3339, info.Created); err == nil {
		meta.CreatedAt = tm
	}

	for pstr, bind := range info.NetworkSettings.Ports {
		if len(bind) > 0 {
			ipproto, port := parsePortString(string(pstr))
			hport, _ := strconv.Atoi(bind[0].HostPort)
			cp := share.CLUSProtoPort{
				Port:    uint16(port),
				IPProto: uint8(ipproto),
			}
			meta.MappedPorts[cp] = &share.CLUSMappedPort{
				CLUSProtoPort: cp,
				HostIP:        net.ParseIP(bind[0].HostIP),
				HostPort:      uint16(hport),
			}
		}
	}

	for _, n := range info.NetworkSettings.Networks {
		meta.Networks.Add(n.NetworkID)
	}

	return meta, nil
}

func (d *dockerDriver) GetImageHistory(name string) ([]*ImageHistory, error) {
	layers, err := d.client.ImageHistory(context.Background(), name)
	if err == nil {
		list := make([]*ImageHistory, len(layers))
		for i, l := range layers {
			list[i] = &ImageHistory{ID: l.ID, Cmd: l.CreatedBy, Size: l.Size}
		}
		return list, nil
	}
	return nil, err
}

func (d *dockerDriver) GetImage(name string) (*ImageMeta, error) {
	info, err := d.client.ImageInspect(context.Background(), name)
	if err == nil {
		meta := &ImageMeta{
			ID:       info.ID,
			Size:     info.Size,
			Author:   info.Author,
			RepoTags: info.RepoTags,
		}

		if tm, err := time.Parse(time.RFC3339, info.Created); err == nil {
			meta.CreatedAt = tm
		}

		if info.Config != nil {
			meta.Env = info.Config.Env
			meta.Labels = info.Config.Labels
		}

		if len(info.RootFS.Layers) > 0 {
			// our order is [0] is the top layer, so we need reverse the layers
			l := len(info.RootFS.Layers)
			meta.Layers = make([]string, l)
			for i, layer := range info.RootFS.Layers {
				meta.Layers[l-i-1] = layer
			}
		} else {
			meta.Layers = make([]string, 0)
		}

		// image name could be:
		//    10.1.127.3:5000/eihmgmt-np/admin:1.85
		// so we need search the last colon
		repo := name
		if i := strings.LastIndex(name, ":"); i > 0 {
			repo = name[:i]
		}

		// repo=index.docker.io/library/redis
		// redis@sha256:6c9f9cb9a250b12c15a92d8042a44f4557c .....
		// it is matched at by its last element
		lastElement := repo
		if tokens := strings.Split(repo, "/"); len(tokens) > 0 {
			lastElement = tokens[len(tokens)-1]
		}

		// get the first completely matched repo
		for _, str := range info.RepoDigests {
			if i := strings.Index(str, "@"); i > 0 {
				if str[:i] == repo { // fully-matched
					meta.Digest = str[i+1:]
					break
				}
			}

			if i := strings.Index(str, "@"); i > 0 {
				if str[:i] == lastElement { // keep the record
					meta.Digest = str[i+1:]
				}
			}
		}

		// remove the sha for local image
		if strings.HasPrefix(meta.ID, "sha") {
			if i := strings.Index(meta.ID, ":"); i > 0 {
				meta.ID = meta.ID[i+1:]
			}
		}

		return meta, nil
	}
	return nil, err
}

func (d *dockerDriver) GetImageFile(id string) (io.ReadCloser, error) {
	resp, err := d.client.ImageSave(context.Background(), []string{id})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get image")
		return nil, err
	}
	return resp, nil
}

// List network doesn't give container list in some network, such as ingress, but inspect gives the detail.
func (d *dockerDriver) GetNetworkEndpoint(netID, container, epName string) (*NetworkEndpoint, error) {
	network, err := d.client.NetworkInspect(context.Background(), netID, dockerNetwork.InspectOptions{})
	if err != nil {
		return nil, err
	}

	for c, ep := range network.Containers {
		if (container == "" || c == container) && ep.Name == epName {
			cnep := &NetworkEndpoint{ID: ep.EndpointID, Name: ep.Name}
			if mac, err := net.ParseMAC(ep.MacAddress); err == nil {
				cnep.MAC = mac
			}
			if ip, subnet, err := net.ParseCIDR(ep.IPv4Address); err == nil {
				cnep.IPNet = &net.IPNet{IP: ip, Mask: subnet.Mask}
			}
			return cnep, nil
		}
	}

	return nil, ErrNotFound
}

func (d *dockerDriver) ListNetworks() (map[string]*Network, error) {
	networks, err := d.client.NetworkList(context.Background(), dockerNetwork.ListOptions{})
	if err != nil {
		return nil, err
	}

	netmap := make(map[string]*Network, len(networks))
	for _, n := range networks {
		network, err := d.client.NetworkInspect(context.Background(), n.ID, dockerNetwork.InspectOptions{})
		if err != nil {
			continue
		}

		nwdata := &Network{
			Name:     network.Name,
			ID:       network.ID,
			Scope:    network.Scope,
			Driver:   network.Driver,
			Subnets:  make([]*net.IPNet, 0),
			Gateways: make([]net.IP, 0),
		}
		for _, ipam := range network.IPAM.Config {
			if _, subnet, err := net.ParseCIDR(ipam.Subnet); err == nil {
				nwdata.Subnets = append(nwdata.Subnets, subnet)
			}
			if ip := net.ParseIP(ipam.Gateway); ip != nil {
				nwdata.Gateways = append(nwdata.Gateways, ip)
			}
		}
		netmap[network.ID] = nwdata
	}

	return netmap, nil
}

func (d *dockerDriver) GetService(id string) (*Service, error) {
	svc, _, err := d.client.ServiceInspectWithRaw(context.Background(), id, dockerTypes.ServiceInspectOptions{})
	if err != nil {
		return nil, err
	}

	r := &Service{
		ID:     svc.ID,
		Name:   svc.Spec.Name,
		Labels: svc.Spec.Labels,
		VIPs:   make([]net.IP, 0, len(svc.Endpoint.VirtualIPs)),
	}
	for _, vip := range svc.Endpoint.VirtualIPs {
		if ip, _, err := net.ParseCIDR(vip.Addr); err == nil {
			r.VIPs = append(r.VIPs, ip)
		}
	}
	return r, nil
}

func (d *dockerDriver) ListServices() ([]*Service, error) {
	svcs, err := d.client.ServiceList(context.Background(), dockerTypes.ServiceListOptions{})
	if err != nil {
		return nil, err
	}

	rs := make([]*Service, len(svcs))
	for i, svc := range svcs {
		r := &Service{
			ID:     svc.ID,
			Name:   svc.Spec.Name,
			Labels: svc.Spec.Labels,
			VIPs:   make([]net.IP, 0, len(svc.Endpoint.VirtualIPs)),
		}
		for _, vip := range svc.Endpoint.VirtualIPs {
			if ip, _, err := net.ParseCIDR(vip.Addr); err == nil {
				r.VIPs = append(r.VIPs, ip)
			}
		}
		rs[i] = r
	}
	return rs, nil
}

func (d *dockerDriver) IsDaemonProcess(proc string, cmds []string) bool {
	return (strings.HasPrefix(proc, "docker") && len(cmds) > 2 && cmds[1] == "daemon") ||
		strings.HasPrefix(proc, "dockerd")
}

func (d *dockerDriver) IsRuntimeProcess(proc string, cmds []string) bool {
	return d.rtProcMap.Contains(proc)
}

func (d *dockerDriver) GetParent(meta *ContainerMetaExtra, pidMap map[int]string) (bool, string) {
	if strings.HasPrefix(meta.NetMode, "container:") {
		return true, meta.NetMode[10:]
	}
	return false, ""
}

func (d *dockerDriver) StopMonitorEvent() {
	d.eventCancel()
}

func (d *dockerDriver) MonitorEvent(cb EventCallback, cpath bool) error {
	var lastSecond time.Time
	var count, sendErr int
	var handler MsgEventCallback

	d.evCallback = cb
	if cpath {
		handler = d.cpEventHandler
	} else {
		handler = d.eventHandler
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	d.eventCancel = cancelCtx

	var bRunning, bTimeoutError bool
	for {
		msgs, errCh := d.client.Events(ctx, dockerEvent.ListOptions{})
		bRunning = true
		bTimeoutError = false
		for bRunning {
			select {
			case event := <-msgs:
				handler(event)
			case err := <-errCh:
				bRunning = false // escape
				bTimeoutError = strings.Contains(err.Error(), "Client.Timeout") || strings.Contains(err.Error(), "deadline exceed")
				if !bTimeoutError {
					log.WithFields(log.Fields{"error": err}).Error("Docker event monitor")
				}
			}
		}

		if bTimeoutError {
			continue
		}

		now := time.Now()
		if now.Sub(lastSecond) > time.Second {
			lastSecond = now
			count = 1
		} else {
			count++

			// More than 10 errors within a second
			if count > 10 {
				count = 0
				if err := d.reConnect(); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Failed to reconnect to docker")

					sendErr++
					if sendErr >= 12 {
						// Notify caller if continously failing for 1 minute
						d.evCallback(EventSocketError, "", 0)
						sendErr = 0
					}

					time.Sleep(5 * time.Second)
				} else {
					sendErr = 0
				}
			}
		}
	}
}

func (d *dockerDriver) cpEventHandler(e dockerEvent.Message) {
	switch e.Type {
	case dockerEvent.ServiceEventType:
		log.WithFields(log.Fields{"event": e}).Debug("")
		switch e.Action {
		case dockerEvent.ActionCreate:
			d.evCallback(EventServiceCreate, e.Actor.ID, 0)
		case dockerEvent.ActionUpdate:
			d.evCallback(EventServiceUpdate, e.Actor.ID, 0)
		case dockerEvent.ActionRemove:
			d.evCallback(EventServiceDelete, e.Actor.ID, 0)
		}
	}
}

func (d *dockerDriver) eventHandler(e dockerEvent.Message) {
	log.WithFields(log.Fields{"event": e}).Debug()
	switch e.Type {
	case dockerEvent.ContainerEventType:
		switch e.Action {
		case dockerEvent.ActionStart:
			d.evCallback(EventContainerStart, e.ID, 0)
		case dockerEvent.ActionKill:
			// To be conservative, ingore only SIGHUP. It is often used to reload config for applications.
			// For example, nginx -s reload
			if sig, ok := e.Actor.Attributes["signal"]; ok && sig == "1" {
				log.WithFields(log.Fields{"signal": sig}).Debug("Ignore event")
				return
			}
			d.evCallback(EventContainerStop, e.ID, 0)
		case dockerEvent.ActionDie:
			d.evCallback(EventContainerStop, e.ID, 0)
		case dockerEvent.ActionDestroy:
			d.evCallback(EventContainerDelete, e.ID, 0)
		case dockerEvent.ActionExtractToDir:
			d.evCallback(EventContainerCopyIn, e.ID, 0)
		case dockerEvent.ActionArchivePath:
			d.evCallback(EventContainerCopyOut, e.ID, 0)
		}
	case dockerEvent.NetworkEventType:
		switch e.Action {
		case dockerEvent.ActionCreate:
			d.evCallback(EventNetworkCreate, e.Actor.ID, 0)
		case dockerEvent.ActionDestroy:
			d.evCallback(EventNetworkDelete, e.Actor.ID, 0)
		}
	}
}

func (d *dockerDriver) GetProxy() (string, string, string) {
	if d.info == nil {
		log.Error("info is nil")
		return "", "", ""
	}
	return d.info.HTTPProxy, d.info.HTTPSProxy, d.info.NoProxy
}

func (d *dockerDriver) GetDefaultRegistries() []string {
	var regNames []string

	if d.info == nil && d.info.RegistryConfig == nil {
		log.Error("info is nil")
		return nil
	}

	for _, inf := range d.info.RegistryConfig.IndexConfigs {
		regNames = append(regNames, inf.Name)
	}
	log.WithFields(log.Fields{"os": d.info.OperatingSystem, "Registries": regNames}).Debug("docker info")

	return regNames
}

func (d *dockerDriver) GetStorageDriver() string {
	if d.info == nil {
		log.Error("info is nil")
		return ""
	}
	return d.info.Driver
}

func isSha256String(input string) bool {
	if len(input) != 64 { // sha256 block size
		return false
	}

	var shaPatterns = regexp.MustCompile("[A-Fa-f0-9]")
	return shaPatterns.MatchString(input)
}

func (d *dockerDriver) getImageRepoTag(imageID, imageName string) string {
	repoTag := imageName
	if imageID != "" { // a valid image ID, look it up in local database
		if !strings.HasPrefix(imageName, "sha256:") && !strings.Contains(imageName, "@sha256:") {
			return imageName // simplest matched form since it could be re-tagged  in native docker env
		}

		image, err := d.client.ImageInspect(context.Background(), imageID)
		if err == nil && len(image.RepoTags) > 0 {
			for _, repo := range image.RepoTags {
				repoTag = repo // report the last one
			}
			//	log.WithFields(log.Fields{"imageID": imageID, "RepoTag": repoTag}).Debug("")
			return repoTag
		}
	}

	// Then, derived it from the 2nd resort(a partial name)
	if strings.HasPrefix(imageName, "sha256:") || isSha256String(imageName) {
		// retrive repoTag
		image, err := d.client.ImageInspect(context.Background(), imageName)
		if err == nil && len(image.RepoTags) > 0 {
			for _, repo := range image.RepoTags {
				repoTag = repo // report the last one
			}
			//	log.WithFields(log.Fields{"imageName": imageName, "RepoTag": repoTag}).Debug("")
			return repoTag
		}
	} else if strings.Contains(imageName, "@sha256:") {
		if images, err := d.client.ImageList(context.Background(), dockerImage.ListOptions{All: true}); err == nil {
			for _, image := range images {
				// log.WithFields(log.Fields{"image": image, "imageName": imageName}).Debug("")
				if len(image.RepoDigests) > 0 && len(image.RepoTags) > 0 {
					for _, repoDigest := range image.RepoDigests {
						if repoDigest == imageName {
							for _, repo := range image.RepoTags {
								repoTag = repo // report the last one
							}
							//				log.WithFields(log.Fields{"imageName": imageName, "RepoTag": repoTag}).Debug("")
							return repoTag
						}
					}
				}
			}
		}
	}
	return repoTag
}
