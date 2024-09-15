package types

import (
	NetNS "github.com/vishvananda/netns"
)

const (
	K8sResourceTypeUnknown   = 0
	K8sResourceTypePod       = 1
	K8sResourceTypeService   = 2
	K8sResourceTypeNamespace = 3
)

type K8sResource struct {
	Type       uint8
	Namespace  string
	Name       string
	Labels     map[string]string
	Containers []string
}

func K8sResourceTypeToString(resourceType uint8) string {
	switch resourceType {
	case K8sResourceTypePod:
		return "Pod"
	case K8sResourceTypeService:
		return "Service"
	case K8sResourceTypeNamespace:
		return "Namespace"
	case K8sResourceTypeUnknown:
		return "Unknown"
	}
	return "Unknown"
}

type Container struct {
	ContainerID    string `json:"containerID"`
	ContainerName  string `json:"containerName"`
	ContainerImage string `json:"containerImage"`

	NamespaceName string `json:"namespaceName"`

	HostPid   uint32 `json:"hostPid"`
	HostMntNS uint32 `json:"hostMntNs"`

	NetNS         uint32         `json:"netns"`
	NetNSHandle   NetNS.NsHandle `json:"netnsfile"`
	NetInterFaces []NetInterface `json:"netInterfaces"`
}

type NetInterface struct {
	InterfaceIndex  int    `json:"interfaceIndex"`
	InterfaceMTU    int    `json:"interfaceMTU"`
	InterfaceName   string `json:"interfaceName"`
	InterfaceHWAddr string `json:"interfaceHWAddr"`
	InterfaceFlags  uint   `json:"interfaceFlags"`
}
