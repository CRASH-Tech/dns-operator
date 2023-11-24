package main

import (
	"time"

	log "github.com/sirupsen/logrus"
)

func metrics() {
	for {
		for _, upstream := range upstreams {
			log.Debugf("UPSTREAM STATUS: %s:%d(%s) ALIVE: %t REQUESTS: %d ANSWERS: %d RCODES: %v QTYPES: %v",
				upstream.Host, upstream.Port,
				upstream.Type,
				upstream.Status.Alive,
				upstream.Status.Requests,
				upstream.Status.Answers,
				upstream.Status.RCodes,
				upstream.Status.QTypes,
			)
			//if upstream.Status.LatencyMeter != nil {
			//log.Println(upstream.Status.LatencyMeter.Calc())
			//}
			log.Println(lm.Meter.Calc())
		}
		log.Debug("=============================")
		time.Sleep(5 * time.Second)
	}

}
