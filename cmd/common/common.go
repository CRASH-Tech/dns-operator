package common

import (
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	LISTEN_TCP       int
	LISTEN_UDP       int
	LOG_LEVEL        string
	LOG_FORMAT       string
	DynamicClient    *dynamic.DynamicClient
	KubernetesClient *kubernetes.Clientset
}
