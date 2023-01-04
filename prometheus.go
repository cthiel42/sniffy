package main

import (
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metric struct {
	lastAccess int64
}

type TTLMap struct {
	m map[string]*metric
	l sync.Mutex
}

var prometheus_expire_after = flag.Int64("prometheus_expire_after", 3600, "After how many seconds of not seeing a metric be updated should that metric be expired and no longer reported. This is a critical configuration for cardinality issues. Expire more frequently if cardinality becomes an issue in the exporter.")
var prometheus_expiration_interval = flag.Int("prometheus_expiration_interval", 60, "How often in seconds the routine that expires metrics should be run")
var PrometheusMetric *prometheus.CounterVec

func startPrometheus() {
	PrometheusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_sent_counter",
			Help: "How many packets have been sent between the .",
		},
		[]string{"sourceMAC", "destinationMAC", "sourceIP", "destinationIP", "sourcePort", "destinationPort", "layer4Protocol", "tcpFlag", "tlsVersion"},
	)
	prometheus.MustRegister(PrometheusMetric)

	// Expose /metrics HTTP endpoint using the created custom registry.
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

}

// Not being used but keeping this here as a template for expansion
func promMetric(SrcIP, DstIP string) {
	// log.Println(SrcIP, DstIP)
	PrometheusMetric.WithLabelValues(SrcIP, DstIP).Inc()
}

func New() (m *TTLMap) {
	m = &TTLMap{m: make(map[string]*metric)}
	go func() {
		for now := range time.Tick(time.Second * time.Duration(*prometheus_expiration_interval)) {
			m.l.Lock()
			for k, v := range m.m {
				if now.Unix()-v.lastAccess > *prometheus_expire_after {
					delete(m.m, k)
				}
			}
			m.l.Unlock()
		}
	}()
	return
}

func (m *TTLMap) Len() int {
	return len(m.m)
}

func (m *TTLMap) Put(k, v string) {
	m.l.Lock()
	it, ok := m.m[k]
	if !ok {
		it = &metric{}
		m.m[k] = it
	}
	it.lastAccess = time.Now().Unix()
	m.l.Unlock()
}

func (m *TTLMap) Get(k string) {
	m.l.Lock()
	if it, ok := m.m[k]; ok {
		it.lastAccess = time.Now().Unix()
	}
	m.l.Unlock()
	return

}
