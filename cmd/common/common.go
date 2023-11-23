package common

import (
	"github.com/jamiealquiza/tachymeter"
	"github.com/miekg/dns"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	LISTEN_ADDRESS  string
	LISTEN_TCP_PORT int
	LISTEN_UDP_PORT int
	LOG_LEVEL       string
	LOG_FORMAT      string
	MAX_PROCS       int
	SO_REUSE_PORTS  int
	COMPRESS        bool
	TIMEOUT_SECONDS int
	//QUEUE_SIZE       int
	PARALLEL_QUERIES int
	DynamicClient    *dynamic.DynamicClient
	KubernetesClient *kubernetes.Clientset
}

type QueryJob struct {
	Msg     *dns.Msg
	RWriter dns.ResponseWriter
}

type Upstream struct {
	Chan         chan QueryJob
	Host         string
	Port         int
	Type         string
	QueueSize    int
	AllowedZones []string //TODO: IMPLEMENT THIS
	Status       UpstreamStatus
}

type UpstreamStatus struct {
	Alive        bool
	Requests     int64
	Answers      int64
	Timeouts     int64
	RCodes       map[int]int64
	QTypes       map[uint16]int64
	LatencyMeter *tachymeter.Tachymeter
}
