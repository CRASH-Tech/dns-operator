package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CRASH-Tech/dns-operator/cmd/common"
	. "github.com/CRASH-Tech/dns-operator/cmd/common"
	"github.com/CRASH-Tech/dns-operator/cmd/kubernetes"

	// "github.com/CRASH-Tech/dns-operator/cmd/kubernetes/api"
	// "github.com/CRASH-Tech/dns-operator/cmd/kubernetes/api/v1alpha1"
	// "github.com/insomniacslk/dhcp/dhcpv4"
	// "github.com/insomniacslk/dhcp/dhcpv4/server4"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	version   = "0.0.7"
	config    common.Config
	kClient   *kubernetes.Client
	namespace string
	hostname  string

	lm    *LatencyMeter
	cache *Cache

	upstreams []*common.Upstream
	//recursiveQueues []chan common.QueryJob

	// leaseExpiration = prometheus.NewGaugeVec(
	// 	prometheus.GaugeOpts{
	// 		Name: "lease_expiration",
	// 		Help: "The time to lease expiration",
	// 	},
	// 	[]string{
	// 		"ip",
	// 		"mac",
	// 		"pool",
	// 		"hostname",
	// 	},
	// )
)

func init() {
	c, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	config = c

	switch config.LOG_FORMAT {
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.SetFormatter(&log.TextFormatter{})
	}

	switch config.LOG_LEVEL {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	var restConfig *rest.Config
	if path, isSet := os.LookupEnv("KUBECONFIG"); isSet {
		log.Printf("Using configuration from '%s'", path)
		restConfig, err = clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Info("Using in-cluster configuration")
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	config.DynamicClient = dynamic.NewForConfigOrDie(restConfig)
	config.KubernetesClient = k8s.NewForConfigOrDie(restConfig)

	//prometheus.MustRegister(leaseExpiration)

	// ns, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	// if err != nil {
	// 	log.Panic(err)
	// }

	// namespace = string(ns)
	// hostname = os.Getenv("HOSTNAME")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kClient = kubernetes.NewClient(ctx, *config.DynamicClient, *config.KubernetesClient)

	//mutex.Lock()

	cache = NewCache()

	lm = NewLM(config.STATS_SAMPLES)

	setUpstreams()
	for _, upstream := range upstreams {
		go upstreamWorker(upstream)
	}

	go metrics()

	var secret string
	// if *tsig != "" {
	// 	a := strings.SplitN(*tsig, ":", 2)
	// 	name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	// }

	//runtime.GOMAXPROCS(config.MAX_PROCS)

	dns.HandleFunc(".", mainHandler)

	for i := 0; i < config.THREADS; i++ { //TODO: CHECK SO_REUSE_PORTS
		go serve("tcp", config.LISTEN_TCP_PORT, secret, config.SO_REUSE_PORTS)
		go serve("udp", config.LISTEN_UDP_PORT, secret, config.SO_REUSE_PORTS)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)

}

func serve(net string, port int, tsig string, soreuseport bool) {
	server := &dns.Server{Addr: fmt.Sprintf("%s:%d", config.LISTEN_ADDRESS, port), Net: net, TsigSecret: nil, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())

	}
	// switch name {
	// case "":
	// 	server := &dns.Server{Addr: "[::]:8053", Net: net, TsigSecret: nil, ReusePort: soreuseport}
	// 	if err := server.ListenAndServe(); err != nil {
	// 		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())

	// 	}
	// default:
	// 	server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}, ReusePort: soreuseport}
	// 	if err := server.ListenAndServe(); err != nil {
	// 		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	// 	}
	// }
}

func isOwnZone(domain string) bool {
	ownZones := []string{"uis.st", "xfix.org"}

	for _, zone := range ownZones {
		if strings.HasSuffix(domain, dns.Fqdn(zone)) {
			return true
		}
	}

	return false
}

func mainHandler(w dns.ResponseWriter, r *dns.Msg) {
	lm.PushStartId(r.Id)

	for _, q := range r.Question {
		if isOwnZone(q.Name) {
			authHandler(w, r, q.Name)
		} else {
			recursorHandler(w, r, q.Name)
		}
	}
}

func connCloser(w dns.ResponseWriter, r *dns.Msg) {
	time.Sleep(time.Duration(config.TIMEOUT_SECONDS) * time.Second)
	if w != nil {
		log.Errorf("Close connention with error %d %s", r.Rcode, w.RemoteAddr().String())

		w.WriteMsg(r)
	}
}
