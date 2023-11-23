package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
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

	mutex     sync.Mutex
	upstreams []common.Upstream
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

	//mutex.Lock()

	setUpstreams()
	for _, upstream := range upstreams {
		go upstreamWorker(upstream)
	}

	lol()

}

func setUpstreams() {
	upstreams = append(upstreams, common.Upstream{
		Host:         "8.8.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, common.Upstream{
		Host:         "8.8.4.4",
		Port:         53,
		Type:         "udp",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, common.Upstream{
		Host:         "77.88.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, common.Upstream{
		Host:         "77.88.8.1",
		Port:         53,
		Type:         "udp",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, common.Upstream{
		Host:         "77.88.8.8",
		Port:         853,
		Type:         "tcp-tls",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, common.Upstream{
		Host:         "195.211.122.1",
		Port:         53,
		Type:         "udp",
		QueueSize:    10,
		Chan:         make(chan common.QueryJob, 10),
		AllowedZones: []string{"uis"},
	})

}

func lol() {
	var secret string
	// if *tsig != "" {
	// 	a := strings.SplitN(*tsig, ":", 2)
	// 	name, secret = dns.Fqdn(a[0]), a[1] // fqdn the name, which everybody forgets...
	// }

	runtime.GOMAXPROCS(config.MAX_PROCS)

	dns.HandleFunc(".", handlerMain)

	for i := 0; i < config.SO_REUSE_PORTS; i++ {
		go serve("tcp", config.LISTEN_TCP_PORT, secret, config.SO_REUSE_PORTS > 1)
		go serve("udp", config.LISTEN_UDP_PORT, secret, config.SO_REUSE_PORTS > 1)
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

func handlerMain(w dns.ResponseWriter, r *dns.Msg) {
	for _, q := range r.Question {
		if isOwnZone(q.Name) {
			handlerOwn(w, r, q.Name)
		} else {
			handlerRecurse(w, r, q.Name)
		}
	}
}

const dom = "whoami.miek.nl."

func handlerOwn(w dns.ResponseWriter, r *dns.Msg, question string) {
	log.Debugf("Received own query: %s", question)

	var (
		//v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = config.COMPRESS

	// if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
	// 	str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
	// 	a = ip.IP
	// 	v4 = a.To4() != nil
	// }
	// if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
	// 	str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
	// 	a = ip.IP
	// 	v4 = a.To4() != nil
	// }

	if a.To4() != nil {
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

	log.Debugf("%v\n", m.String())

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

func handlerRecurse(w dns.ResponseWriter, r *dns.Msg, question string) {

	rand.Shuffle(len(upstreams), func(i, j int) { upstreams[i], upstreams[j] = upstreams[j], upstreams[i] })

	i := 1
	for _, upstream := range upstreams {
		if i <= config.PARALLEL_QUERIES {
			query := common.QueryJob{
				Msg:     r,
				RWriter: w,
			}
			select {
			case upstream.Chan <- query:
				log.Debugf("Send query %s(%d) to upstream %s:%d(%s)", query.Msg.Question[0].Name, query.Msg.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)
				i++
			default:
				log.Warnf("Cannot send query %s(%d) to upstream %s:%d(%s) queue full", query.Msg.Question[0].Name, query.Msg.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)
			}
		}
	}

	if i <= config.PARALLEL_QUERIES {
		log.Errorf("Cannot send query no avialable upstreams!")
	}

}

func upstreamWorker(upstream common.Upstream) {
	log.Infof("Started upstream worker %s:%d(%s)", upstream.Host, upstream.Port, upstream.Type)

	client := dns.Client{
		Net: upstream.Type,
	}

	for query := range upstream.Chan {
		log.Debugf("Received query %s(%d) resolving via %s:%d(%s)", query.Msg.Question[0].Name, query.Msg.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)

		resp, _, err := client.Exchange(query.Msg, fmt.Sprintf("%s:%d", upstream.Host, upstream.Port))
		if err != nil {
			log.Errorf("failed to exchange: %v", err)
			go connCloser(query.RWriter, resp)
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			log.Errorf("failed to get an valid answer\n%v", resp)
			go connCloser(query.RWriter, resp)
			continue
		}

		log.Debugf("Received responce %s(%d) resolved via %s:%d(%s)", resp.Question[0].Name, resp.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)
		query.RWriter.WriteMsg(resp)
	}
}

func connCloser(w dns.ResponseWriter, r *dns.Msg) {
	time.Sleep(time.Duration(config.TIMEOUT_SECONDS) * time.Second)
	log.Warnf("Close connention with error %d %s", r.Rcode, w.RemoteAddr().String())

	w.WriteMsg(r)
}
