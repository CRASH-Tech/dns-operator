package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CRASH-Tech/dns-operator/cmd/common"
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

	mutex sync.Mutex

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

	ns, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Panic(err)
	}

	namespace = string(ns)
	hostname = os.Getenv("HOSTNAME")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kClient = kubernetes.NewClient(ctx, *config.DynamicClient, *config.KubernetesClient)

	mutex.Lock()

	log.Info("WORK!")
	handler()
}

func worker() {
	log.Infof("Starting dns-operator %s", version)
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				metrics()
			}
		}
	}()

}

func metrics() {
	// leases, err := kClient.V1alpha1().Lease().GetAll()
	// if err != nil {
	// 	log.Error(err)

	// 	return
	// }

	// for _, lease := range leases {
	// 	ends, err := strconv.ParseInt(lease.Status.Ends, 10, 64)
	// 	if err != nil {
	// 		log.Error(err)

	// 		continue
	// 	}

	// 	leaseExpiration.WithLabelValues(
	// 		lease.Spec.Ip,
	// 		lease.Spec.Mac,
	// 		lease.Spec.Pool,
	// 		lease.Status.Hostname,
	// 	).Set(float64(ends - time.Now().Unix()))
	// }
}

// /////////////////////////////////////////////
var (
	cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
	printf      = flag.Bool("print", false, "print replies")
	compress    = flag.Bool("compress", false, "compress replies")
	tsig        = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu         = flag.Int("cpu", 0, "number of cpu to use")
)

const dom = "whoami.miek.nl."

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	if v4 {
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   a.To4(),
		}
	} else {
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: a,
		}
	}

	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{str},
	}

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)
	case dns.TypeAXFR, dns.TypeIXFR:
		c := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		defer close(c)
		if err := tr.Out(w, r, c); err != nil {
			return
		}
		soa, _ := dns.NewRR(`whoami.miek.nl. 0 IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
		c <- &dns.Envelope{RR: []dns.RR{soa, t, rr, soa}}
		w.Hijack()
		// w.Close() // Client closes connection
		return
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	// set TC when question is tc.miek.nl.
	if m.Question[0].Name == "tc.miek.nl." {
		m.Truncated = true
		// send half a message
		buf, _ := m.Pack()
		w.Write(buf[:len(buf)/2])
		return
	}
	w.WriteMsg(m)
}

func serve(net, name, secret string, soreuseport bool) {
	switch name {
	case "":
		server := &dns.Server{Addr: "[::]:8053", Net: net, TsigSecret: nil, ReusePort: soreuseport}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())

		}
	default:
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}, ReusePort: soreuseport}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func handler() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *cpu != 0 {
		runtime.GOMAXPROCS(*cpu)
	}
	dns.HandleFunc("miek.nl.", handleReflect)
	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go serve("tcp", name, secret, true)
			go serve("udp", name, secret, true)
		}
	} else {
		go serve("tcp", name, secret, false)
		go serve("udp", name, secret, false)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
