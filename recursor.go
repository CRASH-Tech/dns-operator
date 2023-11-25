package main

import (
	"fmt"
	"math/rand"

	. "github.com/CRASH-Tech/dns-operator/cmd/common"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func setUpstreams() {
	upstreams = append(upstreams, &Upstream{
		Host:         "8.8.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &Upstream{
		Host:         "8.8.4.4",
		Port:         53,
		Type:         "udp",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &Upstream{
		Host:         "77.88.8.8",
		Port:         53,
		Type:         "udp",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &Upstream{
		Host:         "77.88.8.1",
		Port:         53,
		Type:         "udp",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	upstreams = append(upstreams, &Upstream{
		Host:         "77.88.8.8",
		Port:         853,
		Type:         "tcp-tls",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

	// upstreams = append(upstreams, &common.Upstream{
	// 	Host:         "195.211.122.1",
	// 	Port:         53,
	// 	Type:         "udp",
	// 	QueueSize:    100000,
	// 	Chan:         make(chan common.QueryJob, 10000),
	// 	AllowedZones: []string{"uis"},
	// })

	upstreams = append(upstreams, &Upstream{
		Host:         "78.28.209.178",
		Port:         53,
		Type:         "udp",
		QueueSize:    100000,
		Chan:         make(chan QueryJob, 10000),
		AllowedZones: []string{"."},
	})

}

func recursorHandler(w dns.ResponseWriter, r *dns.Msg, question string) {
	rand.Shuffle(len(upstreams), func(i, j int) { upstreams[i], upstreams[j] = upstreams[j], upstreams[i] })

	i := 1
	for _, upstream := range upstreams {
		if i <= config.PARALLEL_QUERIES {
			query := QueryJob{
				Msg:     r,
				RWriter: w,
			}
			select {
			case upstream.Chan <- query:
				log.Debugf("Send query %v to upstream %s:%d(%s)", query.Msg, upstream.Host, upstream.Port, upstream.Type)
				i++
			default:
				log.Warnf("Cannot send query %v to upstream %s:%d(%s) queue full", query.Msg, upstream.Host, upstream.Port, upstream.Type)
			}
		}
	}

	if i <= config.PARALLEL_QUERIES {
		log.Errorf("Cannot send query no avialable upstreams!")
	}

}

func upstreamWorker(upstream *Upstream) {
	log.Infof("Started upstream worker %s:%d(%s)", upstream.Host, upstream.Port, upstream.Type)

	upstream.Status.LM = NewLM(config.STATS_SAMPLES)
	upstream.Status.QTypes = make(map[uint16]int64)
	upstream.Status.RCodes = make(map[int]int64)

	client := dns.Client{
		Net: upstream.Type,
	}

	for query := range upstream.Chan {
		log.Error("lol")
		upstream.Status.LM.PushStart()
		log.Debugf("Received query %v resolving via %s:%d(%s)", query.Msg, upstream.Host, upstream.Port, upstream.Type)

		upstream.Status.Alive = true

		queryHash := Hash(query.Msg.Question)
		// cacheRR := cache.Get(queryHash)
		// if len(cacheRR) > 0 {
		// 	m := new(dns.Msg)
		// 	m.SetReply(query.Msg)
		// 	m.Answer = cacheRR

		// 	upstream.Status.Answers++
		// 	upstream.Status.RCodes[0]++

		// 	log.Debug("Send reply to client")
		// 	rand.Shuffle(len(m.Answer), func(i, j int) { m.Answer[i], m.Answer[j] = m.Answer[j], m.Answer[i] }) //RANDOM RRs
		// 	query.RWriter.WriteMsg(m)

		// 	upstream.Status.LM.PushEnd()
		// 	lm.PushEndId(query.Msg.Id)

		// 	continue
		// }

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

		log.Debugf("Received responce %v resolved via %s:%d(%s)", resp.Answer, upstream.Host, upstream.Port, upstream.Type)
		upstream.Status.Answers++
		upstream.Status.RCodes[resp.Rcode]++

		if config.ADD_TTL_SECONDS > 0 {
			var oRRs []dns.RR
			for _, rr := range resp.Answer {
				rr.Header().Ttl += uint32(config.ADD_TTL_SECONDS)
				oRRs = append(oRRs, rr)
			}
			resp.Answer = oRRs
		}

		log.Debug("Send reply to client")
		rand.Shuffle(len(resp.Answer), func(i, j int) { resp.Answer[i], resp.Answer[j] = resp.Answer[j], resp.Answer[i] }) //RANDOM RRs
		query.RWriter.WriteMsg(resp)

		upstream.Status.LM.PushEnd()
		lm.PushEndId(query.Msg.Id)

		cache.Put(queryHash, resp.Answer)
	}
}
