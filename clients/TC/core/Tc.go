package core

import (
	"TC/bpf"
	"TC/container"
	"TC/k8s"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var StopChan chan struct{}

func init() {
	StopChan = make(chan struct{})
}

type AckService struct {
	waitGroup *sync.WaitGroup
}

func NewAck() *AckService {
	ak := new(AckService)
	ak.waitGroup = new(sync.WaitGroup)
	return ak
}

func (ak *AckService) DestroyAck() {
	close(StopChan)

	log.Print("[SentryFlow] Waiting for routine terminations")
	ak.waitGroup.Wait()
	log.Print("[SentryFlow] Terminated SentryFlow")
}

func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

func Tc() {
	ak := NewAck()

	// k8s
	if !k8s.InitK8sClient() {
		ak.DestroyAck()
		return
	}

	go container.MonitorContainerdEvents()
	log.Printf("[ACK] Start Wathcing Container\n")
	bpf.ApplyTcToContainer()

	k8s.RunInformers(StopChan, ak.waitGroup)

	sigChan := GetOSSigChannel()
	<-sigChan
	ak.DestroyAck()
}
