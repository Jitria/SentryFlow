package k8s

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var K8sH *KubernetesHandler

///////////////////////
//  make k8shandler  //
///////////////////////

func init() {
	K8sH = NewK8sHandler()
}

type KubernetesHandler struct {
	Cri       string
	clientSet *kubernetes.Clientset

	watchers  map[string]*cache.ListWatch
	informers map[string]cache.Controller

	PodMap       map[string]*corev1.Pod
	ServiceMap   map[string]*corev1.Service
	NamespaceMap map[string]*corev1.Namespace

	CRI       string
	DynClient *dynamic.DynamicClient
}

func NewK8sHandler() *KubernetesHandler {
	kh := &KubernetesHandler{
		Cri:       getCRISocket(),
		watchers:  make(map[string]*cache.ListWatch),
		informers: make(map[string]cache.Controller),

		PodMap:       make(map[string]*corev1.Pod),
		ServiceMap:   make(map[string]*corev1.Service),
		NamespaceMap: make(map[string]*corev1.Namespace),
	}

	return kh
}

var ContainerRuntimeSocketMap = map[string][]string{
	"containerd": {
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
	},
}

func getCRISocket() string {
	for k := range ContainerRuntimeSocketMap {
		for _, candidate := range ContainerRuntimeSocketMap[k] {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}

////////////////////////
//  init  k8shandler  //
////////////////////////

func InitK8sClient() bool {
	var err error

	kubeconfig := os.Getenv("HOME") + "/.kube/config"
	if _, err := os.Stat(filepath.Clean(kubeconfig)); err != nil {
		return false
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return false
	}

	K8sH.clientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}

	K8sH.DynClient, err = dynamic.NewForConfig(config)
	if err != nil {
		return false
	}
	log.Printf("K8sH.ClientSet: %v", K8sH.clientSet)
	K8sH.getExistingResources()

	watchTargets := []string{"pods", "services", "namespaces"}

	for _, target := range watchTargets {
		watcher := cache.NewListWatchFromClient(
			K8sH.clientSet.CoreV1().RESTClient(),
			target,
			corev1.NamespaceAll,
			fields.Everything(),
		)
		K8sH.watchers[target] = watcher
	}

	K8sH.initInformers()

	log.Print("[InitK8sClient] Initialized Kubernetes client")

	return true
}

//////////////////////////////
//  get Existing Resources  //
//////////////////////////////

func (k8s *KubernetesHandler) getExistingResources() {
	podList, err := k8s.clientSet.CoreV1().Pods(corev1.NamespaceAll).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Printf("[K8s] Failed to get Pods: %v", err.Error())
	}

	for _, pod := range podList.Items {
		currentPod := pod
		k8s.PodMap[pod.Status.PodIP] = &currentPod
		log.Printf("[K8s] Add existing pod %s: %s/%s", pod.Status.PodIP, pod.Namespace, pod.Name)
	}

	serviceList, err := k8s.clientSet.CoreV1().Services(corev1.NamespaceAll).List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Printf("[K8s] Failed to get Services: %v", err.Error())
	}

	for _, service := range serviceList.Items {
		currentService := service

		if service.Spec.Type == "LoadBalancer" {
			for _, lbIngress := range service.Status.LoadBalancer.Ingress {
				lbIP := lbIngress.IP
				if lbIP != "" {
					k8s.ServiceMap[lbIP] = &currentService
					log.Printf("[K8s] Add existing service (LoadBalancer) %s: %s/%s", lbIP, service.Namespace, service.Name)
				}
			}
		} else {
			k8s.ServiceMap[service.Spec.ClusterIP] = &currentService
			if len(service.Spec.ExternalIPs) != 0 {
				for _, eIP := range service.Spec.ExternalIPs {
					k8s.ServiceMap[eIP] = &currentService
					log.Printf("[K8s] Add existing service %s: %s/%s", eIP, service.Namespace, service.Name)
				}
			}
		}
	}

	namespaceList, err := k8s.clientSet.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Printf("[K8s] Failed to get Namespaces: %v", err.Error())
	}

	for _, namespace := range namespaceList.Items {
		currentNamespace := namespace
		k8s.NamespaceMap[namespace.Name] = &currentNamespace
		log.Printf("[K8s] Add existing namespace: %s", namespace.Name)
	}
}

/////////////////////
//  init informer  //
/////////////////////

func (k8s *KubernetesHandler) initInformers() {
	_, pc := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: k8s.watchers["pods"],
		ObjectType:    &corev1.Pod{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				k8s.PodMap[pod.Status.PodIP] = pod
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newPod := newObj.(*corev1.Pod)
				k8s.PodMap[newPod.Status.PodIP] = newPod
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				delete(k8s.PodMap, pod.Status.PodIP)
			},
		},
		ResyncPeriod: time.Second * 0,
	})

	k8s.informers["pods"] = pc

	_, sc := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: k8s.watchers["services"],
		ObjectType:    &corev1.Service{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				service := obj.(*corev1.Service)

				if service.Spec.Type == "LoadBalancer" {
					for _, lbIngress := range service.Status.LoadBalancer.Ingress {
						lbIP := lbIngress.IP
						if lbIP != "" {
							k8s.ServiceMap[lbIP] = service
						}
					}
				} else {
					k8s.ServiceMap[service.Spec.ClusterIP] = service
					if len(service.Spec.ExternalIPs) != 0 {
						for _, eIP := range service.Spec.ExternalIPs {
							k8s.ServiceMap[eIP] = service
						}
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				newService := newObj.(*corev1.Service)
				if newService.Spec.Type == "LoadBalancer" {
					for _, lbIngress := range newService.Status.LoadBalancer.Ingress {
						lbIP := lbIngress.IP
						if lbIP != "" {
							k8s.ServiceMap[lbIP] = newService
						}
					}
				} else {
					k8s.ServiceMap[newService.Spec.ClusterIP] = newService
					if len(newService.Spec.ExternalIPs) != 0 {
						for _, eIP := range newService.Spec.ExternalIPs {
							k8s.ServiceMap[eIP] = newService
						}
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				service := obj.(*corev1.Service)
				if service.Spec.Type == "LoadBalancer" {
					for _, lbIngress := range service.Status.LoadBalancer.Ingress {
						lbIP := lbIngress.IP
						if lbIP != "" {
							delete(k8s.ServiceMap, lbIP)
						}
					}
				} else {
					delete(k8s.ServiceMap, service.Spec.ClusterIP)
					if len(service.Spec.ExternalIPs) != 0 {
						for _, eIP := range service.Spec.ExternalIPs {
							delete(k8s.ServiceMap, eIP)
						}
					}
				}
			},
		},
		ResyncPeriod: time.Second * 0,
	})

	k8s.informers["services"] = sc

	_, nc := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: k8s.watchers["namespaces"],
		ObjectType:    &corev1.Namespace{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				namespace := obj.(*corev1.Namespace)
				k8s.NamespaceMap[namespace.Name] = namespace
				log.Printf("[K8s] Namespace added: %s", namespace.Name)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				namespace := newObj.(*corev1.Namespace)
				k8s.NamespaceMap[namespace.Name] = namespace
				log.Printf("[K8s] Namespace updated: %s", namespace.Name)
			},
			DeleteFunc: func(obj interface{}) {
				namespace := obj.(*corev1.Namespace)
				delete(k8s.NamespaceMap, namespace.Name)
				log.Printf("[K8s] Namespace deleted: %s", namespace.Name)
			},
		},
		ResyncPeriod: time.Second * 0,
	})

	k8s.informers["namespaces"] = nc
}

// run informer
func RunInformers(stopChan chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)

	for name, informer := range K8sH.informers {
		name := name
		informer := informer
		go func() {
			log.Printf("[RunInformers] Starting an informer for %s", name)
			informer.Run(stopChan)
			defer wg.Done()
		}()
	}

	log.Print("[RunInformers] Started all Kubernetes informers")
}
