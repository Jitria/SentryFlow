package bpf

import (
	"TC/container"
	"TC/types"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	tccore "github.com/florianl/go-tc/core"
	NetNS "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type packet bpf bpf.c -- -I../headers

var BpfH *BpfHandler

func init() {
	var err error

	BpfH = NewTcHandler()
	if err := loadBpfObjects(&BpfH.Objects, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %s", err)
	}

	if BpfH.Reader, err = ringbuf.NewReader(BpfH.Objects.PacketResultMap); err != nil {
		log.Fatalf("fail to make new reader : %s", err)
	}
}

type BpfHandler struct {
	Objects      bpfObjects
	Reader       *ringbuf.Reader
	Record       chan ringbuf.Record
	ContainerMap map[string]types.Container
}

func NewTcHandler() *BpfHandler {
	ch := &BpfHandler{}

	return ch
}

func ApplyTcToContainer() {

	var err error

	BpfH = NewTcHandler()
	if err = rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("fail to remove memory lock: %s", err)
	}
	if err := loadBpfObjects(&BpfH.Objects, nil); err != nil {
		log.Printf("Failed to load eBPF objects: %s\n", err)
	}

	log.Printf("Success to load eBPF objects\n")

	if BpfH.Reader, err = ringbuf.NewReader(BpfH.Objects.PacketResultMap); err != nil {
		log.Printf("fail to make new reader : %s\n", err)
	}

	log.Printf("Success to make new reader")

	BpfH.Record = make(chan ringbuf.Record)
	BpfH.ContainerMap = make(map[string]types.Container)

	go readRecords(BpfH.Reader, BpfH.Record)
	go showEvent(BpfH.Record)

	for {
		for _, container := range container.ContainerdClient.ContainerMap {
			if _, value := BpfH.ContainerMap[container.ContainerID]; !value {
				log.Printf("Success to add new container for TC: %s\n", container.ContainerID)
				BpfH.ContainerMap[container.ContainerID] = container
				go func() {
					for _, iface := range container.NetInterFaces {
						runInspector(iface.InterfaceIndex, container.NetNSHandle)
					}
				}()
			}
		}
		time.Sleep(1 * time.Second)
	}
}

func readRecords(reader *ringbuf.Reader, c chan ringbuf.Record) {
	for {
		record, err := reader.Read()
		if err != nil {
			log.Panicf("fail to read: %s", err)
			close(c)
			return
		}
		c <- record
	}
}

func IntToIPString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func showEvent(channel chan ringbuf.Record) {
	for {
		select {
		case record := <-channel:
			var event bpfPacket

			err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("fail to read kprobe record: %s, data: %v\n", err, record.RawSample)
				continue
			}

			srcIP := IntToIPString(uint32(event.SrcIp))
			destPort := IntToIPString(uint32(event.DstIp))
			fmt.Printf("SrcIp: %s\n", srcIP)
			fmt.Printf("SrcPort: %d\n", event.SrcPort)
			fmt.Printf("DstIp: %s\n", destPort)
			fmt.Printf("DstPort: %d\n", event.DstPort)
			fmt.Printf("X_requestId: %s\n", event.X_requestId)
			fmt.Printf("===============================\n")

		}
	}
}

func runInspector(iface int, nshandle NetNS.NsHandle) {
	err := NetNS.Set(nshandle)
	if err != nil {
		log.Printf("setting network namespace: %v", err)
		return
	}

	ifname, err := net.InterfaceByIndex(iface)
	if err != nil {
		log.Printf("failed to get interface by index: %v", err)
		return
	}

	tcnl, _ := attachTC(ifname, nshandle, BpfH.Objects)
	if tcnl == nil {
		log.Printf("attaching TC(tcnl): %v", err)
		return
	}
}

func attachTC(iface *net.Interface, nshandle NetNS.NsHandle, objs bpfObjects) (*tc.Tc, tc.Object) {

	err := NetNS.Set(nshandle)
	if err != nil {
		log.Printf("setting network namespace: %v", err)
		return nil, tc.Object{}
	}

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Printf("could not open netlink socket: %v", err)
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  tccore.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	err = tcnl.Qdisc().Replace(&qdisc)
	if err != nil {
		log.Printf("could not assign Ingress clsact to "+iface.Name+" : ", err)
		return nil, tc.Object{}
	}

	infd := uint32(objs.bpfPrograms.PacketAnalyzerAgent.FD())
	egfd := uint32(objs.bpfPrograms.PacketAnalyzerAgent.FD())

	if err = AddFilter(infd, iface, tc.HandleMinIngress, tcnl); err != nil {
		log.Printf("could not attach Ingress filter for eBPF program: %s", err)
		return nil, tc.Object{}
	}
	if err = AddFilter(egfd, iface, tc.HandleMinEgress, tcnl); err != nil {
		log.Printf("could not attach Egress filter for eBPF program: %s", err)
		return nil, tc.Object{}
	}

	return tcnl, qdisc
}

func AddFilter(fd uint32, iface *net.Interface, handle uint32, tcnl *tc.Tc) error {
	flags := uint32(0x1)

	filterIn := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  tccore.BuildHandle(tc.HandleRoot, handle),
			Info:    0x10300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	err := tcnl.Filter().Add(&filterIn)
	if err != nil {
		log.Printf("could not attach Ingress filter for eBPF program: %s", err)
		return err
	}

	return nil
}
