package main

import (
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func authHandler(w dns.ResponseWriter, r *dns.Msg, question string) {
	log.Debugf("Received own query: %s", question)

	var (
	//v4  bool
	//rr dns.RR
	//	str string
	//	a   net.IP
	)

	m := new(dns.Msg)
	m.SetReply(r)
	//m.Compress = config.COMPRESS

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Info("Received A req")
		// rr := &dns.A{
		// 	Hdr: dns.RR_Header{Name: "test.uis.st.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		// 	A:   net.ParseIP("192.100.10.4"),
		// }

		//m.Answer = append(m.Answer, &getARecords()[])
		for _, a := range getARecords() {
			m.Answer = append(m.Answer, a)
		}
		//m.Answer = getARecords()

		w.WriteMsg(m)
	default:
		log.Errorf("unknown msg type %v", r.Question[0].Qtype)

	}

	//w.WriteMsg(m)
}

func getARecords() (result []*dns.A) {
	ips := []string{"192.168.0.1", "192.168.0.2"}

	for _, ip := range ips {
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: "test.uis.st.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		}
		//rr := dns.RR{}
		result = append(result, rr)
	}

	return
}

//const dom = "whoami.miek.nl."

// func badHandler(w dns.ResponseWriter, r *dns.Msg, question string) {
// 	log.Debugf("Received own query: %s", question)

// 	var (
// 		//v4  bool
// 		rr  dns.RR
// 		str string
// 		a   net.IP
// 	)

// 	m := new(dns.Msg)
// 	m.SetReply(r)
// 	m.Compress = config.COMPRESS

// 	if a.To4() != nil {
// 		rr = &dns.A{
// 			Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
// 			A:   a.To4(),
// 		}
// 	} else {
// 		rr = &dns.AAAA{
// 			Hdr:  dns.RR_Header{Name: dom, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
// 			AAAA: a,
// 		}
// 	}

// 	t := &dns.TXT{
// 		Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
// 		Txt: []string{str},
// 	}

// 	switch r.Question[0].Qtype {
// 	case dns.TypeTXT:
// 		m.Answer = append(m.Answer, t)
// 		m.Extra = append(m.Extra, rr)
// 	default:
// 		fallthrough
// 	case dns.TypeAAAA, dns.TypeA:
// 		m.Answer = append(m.Answer, rr)
// 		m.Extra = append(m.Extra, t)
// 	case dns.TypeAXFR, dns.TypeIXFR:
// 		c := make(chan *dns.Envelope)
// 		tr := new(dns.Transfer)
// 		defer close(c)
// 		if err := tr.Out(w, r, c); err != nil {
// 			return
// 		}
// 		soa, _ := dns.NewRR(`whoami.miek.nl. 0 IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
// 		c <- &dns.Envelope{RR: []dns.RR{soa, t, rr, soa}}
// 		w.Hijack()
// 		// w.Close() // Client closes connection
// 		return
// 	}

// 	if r.IsTsig() != nil {
// 		if w.TsigStatus() == nil {
// 			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
// 		} else {
// 			println("Status", w.TsigStatus().Error())
// 		}
// 	}

// 	log.Debugf("%v\n", m.String())

// 	// set TC when question is tc.miek.nl.
// 	if m.Question[0].Name == "tc.miek.nl." {
// 		m.Truncated = true
// 		// send half a message
// 		buf, _ := m.Pack()
// 		w.Write(buf[:len(buf)/2])
// 		return
// 	}
// 	w.WriteMsg(m)
// }
