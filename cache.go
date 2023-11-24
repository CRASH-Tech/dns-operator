package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	cache     map[string][]CacheRR
	cacheLock sync.RWMutex
)

type Cache struct {
	Name  string
	RType uint16
}

type CacheRR struct {
	dns.RR
	Expire time.Time
}

func cacheCleaner() {
	for {
		cacheLock.RLock()
		oldCache := cache
		cacheLock.RUnlock()

		newCache := make(map[Cache][]CacheRR)
		now := time.Now()

		for k, cacheRRs := range oldCache {
			for _, cacheRR := range cacheRRs {
				if !now.After(cacheRR.Expire) {
					newCache[k] = append(newCache[k], cacheRR)
				}
			}
		}

		cacheLock.Lock()
		cache = newCache
		cacheLock.Unlock()

		time.Sleep(10 * time.Second)
	}
}

func getFromCache(n string, t uint16) []dns.RR {
	cacheLock.RLock()
	c := cache
	cacheLock.RUnlock()

	//var result []dns.RR
	for k, cacheRRs := range c {
		if k.Name == n && k.RType == t {
			for _, cacheRR := range cacheRRs {
				log.Errorf("append %v", cacheRR)
				//result = append(result, cacheRR)
			}
			//log.Errorf("found in cache: %v", cacheRRs)
		}
	}

	//log.Errorf("Not found in cache: %s", n)
	return nil
}

func putToCache(rrs []dns.RR) {
	//return
	cacheLock.Lock()

	//cacheLock.RLock()
	newCache := cache
	//cacheLock.RUnlock()

	for _, rr := range rrs {
		c := Cache{
			Name:  rr.Header().Name,
			RType: rr.Header().Rrtype,
		}
		cacheRR := CacheRR{
			RR:     rr,
			Expire: time.Now().Add(time.Duration(int(rr.Header().Ttl)) * time.Second),
		}
		newCache[c] = append(newCache[c], cacheRR)
	}

	// cacheLock.Lock()
	cache = newCache
	cacheLock.Unlock()
}
