package container

import (
	"TC/k8s"
	"TC/types"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	containersv1 "github.com/containerd/containerd/api/services/containers/v1"
	tasksv1 "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/namespaces"
	NetNS "github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var ContainerdClient *containerdClientstruct

type containerdClientstruct struct {
	containersClient containersv1.ContainersClient
	tasksClient      tasksv1.TasksClient
	context          context.Context
	ContainerMap     map[string]types.Container
}

/*************************/
/* StartContainerMonitor */
/*************************/
func initContainerdClient() {
	ContainerdClient = &containerdClientstruct{}
	k8s.K8sH.Cri = "unix://" + k8s.K8sH.Cri

	creds := insecure.NewCredentials()
	conn, err := grpc.Dial(k8s.K8sH.Cri, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Printf("failed to get containerd's client : %v", err)
		return
	}

	ContainerdClient.containersClient = containersv1.NewContainersClient(conn)
	ContainerdClient.tasksClient = tasksv1.NewTasksClient(conn)
	ContainerdClient.context = namespaces.WithNamespace(context.Background(), "k8s.io")
	ContainerdClient.ContainerMap = make(map[string]types.Container)
}

func MonitorContainerdEvents() {
	initContainerdClient()
	getContainerInfo()

}

/**********************/
/*  GetContainerinfo  */
/**********************/
func getContainerInfo() {
	req := containersv1.ListContainersRequest{}

	for {
		if containerList, err := ContainerdClient.containersClient.List(ContainerdClient.context, &req); err == nil {
			for _, container := range containerList.Containers {
				var inspect *containersv1.GetContainerResponse
				containersreq := containersv1.GetContainerRequest{ID: container.ID}
				if inspect, err = ContainerdClient.containersClient.Get(ContainerdClient.context, &containersreq); err != nil {
					log.Printf("failed to get container context : %v", err)
				}

				if _, value := ContainerdClient.ContainerMap[inspect.Container.ID]; value {
					continue
				}

				log.Printf("[Containerd] find new container: %s\n", inspect.Container.ID)
				var onecontainer types.Container
				onecontainer.ContainerID = inspect.Container.ID
				onecontainer.ContainerImage = inspect.Container.Image
				onecontainer.ContainerName = inspect.Container.ID

				containerLabels := inspect.Container.Labels
				if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
					if val, exist := containerLabels["io.kubernetes.pod.namespace"]; exist {
						onecontainer.NamespaceName = val
					}
				} else {
					onecontainer.NamespaceName = ""
				}

				tasksReq := tasksv1.ListPidsRequest{ContainerID: onecontainer.ContainerID}
				if tasksRes, err := ContainerdClient.tasksClient.ListPids(ContainerdClient.context, &tasksReq); err == nil {
					pid := strconv.Itoa(int(tasksRes.Processes[0].Pid))

					if data, err := os.Readlink("/proc/" + pid + "/ns/pid"); err == nil {
						if _, err := fmt.Sscanf(data, "pid:[%d]\n", &onecontainer.HostPid); err != nil {
							log.Printf("fail to get host pid assigned to  %s : %s\n", onecontainer.ContainerID, err)
						}
					}

					if data, err := os.Readlink("/proc/" + pid + "/ns/mnt"); err == nil {
						if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &onecontainer.HostMntNS); err != nil {
							log.Printf("fail to get host mountnamespace assigned to  %s : %s\n", onecontainer.ContainerID, err)
						}
					}

					if data, err := os.Readlink("/proc/" + pid + "/ns/net"); err == nil {
						if _, err = fmt.Sscanf(data, "net:[%d]\n", &onecontainer.NetNS); err != nil {
							log.Printf("fail to get container network assigned to  %s : %s\n", onecontainer.ContainerID, err)
						}

						onecontainer.NetNSHandle, err = NetNS.GetFromPath("/proc/" + pid + "/ns/net")
						if err != nil {
							log.Printf("unable to get NetNSHandle (%s): %v", pid, err)
						}

						onecontainer.NetInterFaces, err = getInterfacebyNetNSHandle(onecontainer.NetNSHandle)
						if err != nil {
							log.Printf("unable to get NetInterface (%s): %v", pid, err)
						}
					}
				}
				ContainerdClient.ContainerMap[onecontainer.ContainerID] = onecontainer
			}
		} else if err != nil {
			log.Printf("hello : %s", err)
		}
		time.Sleep(1 * time.Second)
	}
}

func getInterfacebyNetNSHandle(nsh NetNS.NsHandle) ([]types.NetInterface, error) {
	var netinterfaces []types.NetInterface

	err := NetNS.Set(nsh)
	if err != nil {
		log.Println("[NetIFHandler]Error setting NS: ", err)
		return []types.NetInterface{}, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println("Error getting IF: ", err)
		return []types.NetInterface{}, err
	}

	for _, iface := range ifaces {
		var netinf types.NetInterface
		netinf.InterfaceName = iface.Name
		netinf.InterfaceIndex = iface.Index
		netinf.InterfaceMTU = iface.MTU
		netinf.InterfaceHWAddr = string(iface.HardwareAddr)
		netinf.InterfaceFlags = uint(iface.Flags)
		netinterfaces = append(netinterfaces, netinf)
	}

	return netinterfaces, nil
}
