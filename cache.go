package main

import (
	"sync"
	"time"

	. "github.com/CRASH-Tech/dns-operator/cmd/common"
	"github.com/miekg/dns"
)

type Cache struct {
	sync.RWMutex
	cache  map[string][]CacheRR
	Status CacheStatus
}

type CacheStatus struct {
	Size     int64
	Requests int64
	Answers  int64
	RCodes   map[int]int64
	QTypes   map[uint16]int64
	LM       *LatencyMeter
}

type CacheRR struct {
	dns.RR
	Expire time.Time
}

func NewCache() *Cache {
	cache := Cache{
		cache: make(map[string][]CacheRR),
	}

	cache.Status.LM = NewLM(config.STATS_SAMPLES)

	go cache.cleaner()

	return &cache
}

func (c *Cache) cleaner() {
	for {
		c.Lock()
		newCache := make(map[string][]CacheRR)
		for hash, cacheRRs := range c.cache {
			for _, rr := range cacheRRs {
				if rr.Expire.After(time.Now()) {
					newCache[hash] = append(newCache[hash], rr)
				}
			}
		}

		c.cache = newCache
		c.Status.Size = int64(len(c.cache))
		c.Unlock()

		time.Sleep(10 * time.Second)
		//log.Errorf("cache size: %d", len(c.cache))
	}
}

func (c *Cache) Get(hash string) []dns.RR {
	c.RLock()
	defer c.RUnlock()

	var result []dns.RR
	for _, rr := range c.cache[hash] {
		result = append(result, rr.RR)
	}

	return result
}

func (c *Cache) Put(hash string, rrs []dns.RR) {
	c.Lock()
	var tmpRRs []dns.RR
	for _, rr := range c.cache[hash] {
		tmpRRs = append(tmpRRs, rr)
	}
	if Hash(rrs) == Hash(tmpRRs) {
		c.Unlock()
		return
	}

	for _, rr := range rrs {
		c.cache[hash] = append(c.cache[hash], CacheRR{
			RR:     rr,
			Expire: time.Now().Add(time.Duration(rr.Header().Ttl) * time.Second),
		})
	}
	c.Unlock()
}
