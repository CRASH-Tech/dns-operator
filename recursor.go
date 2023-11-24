package main

import (
	"fmt"
	"math/rand"

	"github.com/CRASH-Tech/dns-operator/cmd/common"
	. "github.com/CRASH-Tech/dns-operator/cmd/common"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func setUpstreams() {
	upstreams = append(upstreams, &common.Upstream{
		Host:         "8.8.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &common.Upstream{
		Host:         "8.8.4.4",
		Port:         53,
		Type:         "udp",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &common.Upstream{
		Host:         "77.88.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &common.Upstream{
		Host:         "77.88.8.1",
		Port:         53,
		Type:         "udp",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &common.Upstream{
		Host:         "77.88.8.8",
		Port:         853,
		Type:         "tcp-tls",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	// upstreams = append(upstreams, &common.Upstream{
	// 	Host:         "195.211.122.1",
	// 	Port:         53,
	// 	Type:         "udp",
	// 	QueueSize:    10000,
	// 	Chan:         make(chan common.QueryJob, 10000),
	// 	AllowedZones: []string{"uis"},
	// })

	upstreams = append(upstreams, &common.Upstream{
		Host:         "78.28.209.178",
		Port:         53,
		Type:         "udp",
		QueueSize:    10000,
		Chan:         make(chan common.QueryJob, 10000),
		AllowedZones: []string{"."},
	})

}

func recursorHandler(w dns.ResponseWriter, r *dns.Msg, question string) {
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

func upstreamWorker(upstream *common.Upstream) {
	log.Infof("Started upstream worker %s:%d(%s)", upstream.Host, upstream.Port, upstream.Type)

	upstream.Status.LM = NewLM(config.STATS_SAMPLES)
	upstream.Status.QTypes = make(map[uint16]int64)
	upstream.Status.RCodes = make(map[int]int64)

	client := dns.Client{
		Net: upstream.Type,
	}

	for query := range upstream.Chan {
		upstream.Status.LM.PushStart()
		log.Debugf("Received query %s(%d) resolving via %s:%d(%s)", query.Msg.Question[0].Name, query.Msg.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)

		upstream.Status.Alive = true
		upstream.Status.Requests++
		upstream.Status.QTypes[query.Msg.Question[0].Qtype]++

		resp, _, err := client.Exchange(query.Msg, fmt.Sprintf("%s:%d", upstream.Host, upstream.Port))
		if err != nil {
			log.Errorf("failed to exchange: %v", err)

			upstream.Status.Timeouts++
			upstream.Status.RCodes[2]++
			lm.PushEndId(query.Msg.Id)

			go connCloser(query.RWriter, query.Msg)
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			log.Errorf("failed to get an valid answer\n%v", resp)

			upstream.Status.RCodes[resp.Rcode]++
			lm.PushEndId(query.Msg.Id)

			go connCloser(query.RWriter, resp)
			continue
		}

		log.Debugf("Received responce %s(%d) resolved via %s:%d(%s)", resp.Question[0].Name, resp.Question[0].Qtype, upstream.Host, upstream.Port, upstream.Type)
		upstream.Status.Answers++
		upstream.Status.RCodes[resp.Rcode]++

		log.Debug("Send reply to client")
		query.RWriter.WriteMsg(resp)

		upstream.Status.LM.PushEnd()
		lm.PushEndId(query.Msg.Id)
	}
}
