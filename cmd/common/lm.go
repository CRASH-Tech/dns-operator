package common

import (
	"sync"
	"time"

	"github.com/jamiealquiza/tachymeter"
)

type LatencyMeter struct {
	sync.RWMutex
	start time.Time
	stats map[uint16]time.Time
	Meter *tachymeter.Tachymeter
}

func NewLM(size int) LatencyMeter {
	lm := LatencyMeter{
		Meter: tachymeter.New(&tachymeter.Config{Size: size}),
		stats: make(map[uint16]time.Time),
	}

	return lm
}

func (lm *LatencyMeter) PushStartId(id uint16) {
	lm.Lock()
	lm.stats[id] = time.Now()
	lm.Unlock()
}

func (lm *LatencyMeter) PushEndId(id uint16) {
	lm.Lock()
	start := lm.stats[id]
	delete(lm.stats, id)
	lm.Unlock()

	if !start.IsZero() {
		lm.Meter.AddTime(time.Since(start))
	}
}

func (lm *LatencyMeter) PushStart() {
	lm.start = time.Now()
}

func (lm *LatencyMeter) PushEnd() {
	if !lm.start.IsZero() {
		lm.Meter.AddTime(time.Since(lm.start))
	}
}
