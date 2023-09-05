package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
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

var PrometheusMetricGeneric *prometheus.CounterVec
var PrometheusMetricIncoming *prometheus.CounterVec
var PrometheusMetricOutgoing *prometheus.CounterVec
var localMAC string
var expirationMap *TTLMap

func startPrometheus(config Config) {
	expirationMap = NewTTLMap(config)

	PrometheusMetricGeneric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_counter",
			Help: "How many packets have been seen between the given source and destination fields. This is used for packets where the source/destination can't be identified as the local machine",
		},
		[]string{"sourceMAC", "destinationMAC", "sourceIP", "destinationIP", "sourcePort", "destinationPort", "layer4Protocol", "tcpFlag", "tlsVersion"},
	)
	prometheus.MustRegister(PrometheusMetricGeneric)

	PrometheusMetricIncoming = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "incoming_packets_counter",
			Help: "How many packets have been seen incoming from the source fields to the local machine",
		},
		[]string{"sourceMAC", "destinationMAC", "sourceIP", "destinationIP", "sourcePort", "destinationPort", "layer4Protocol", "tcpFlag", "tlsVersion"},
	)
	prometheus.MustRegister(PrometheusMetricIncoming)

	PrometheusMetricOutgoing = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "outgoing_packets_counter",
			Help: "How many packets have been seen outgoing from the local machine to the destination fields",
		},
		[]string{"sourceMAC", "destinationMAC", "sourceIP", "destinationIP", "sourcePort", "destinationPort", "layer4Protocol", "tcpFlag", "tlsVersion"},
	)
	prometheus.MustRegister(PrometheusMetricOutgoing)

	// Expose /metrics HTTP endpoint using the created custom registry.
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(config.PROMETHEUS_OUTPUT.PROMETHEUS_METRICS_PORT), nil))
	}()

}

func postPromethetheusMetric(packetData PacketData) {
	expirationMap.TTLMapPut(makeKeyFromPacketData(packetData))
	if localMAC == packetData.sourceMAC {
		PrometheusMetricOutgoing.WithLabelValues(packetData.sourceMAC, packetData.destinationMAC, packetData.sourceIP, packetData.destinationIP, packetData.sourcePort, packetData.destinationPort, packetData.layer4Protocol, packetData.tcpFlag, packetData.tlsVersion).Inc()
	} else if localMAC == packetData.destinationMAC {
		PrometheusMetricIncoming.WithLabelValues(packetData.sourceMAC, packetData.destinationMAC, packetData.sourceIP, packetData.destinationIP, packetData.sourcePort, packetData.destinationPort, packetData.layer4Protocol, packetData.tcpFlag, packetData.tlsVersion).Inc()
	} else {
		PrometheusMetricGeneric.WithLabelValues(packetData.sourceMAC, packetData.destinationMAC, packetData.sourceIP, packetData.destinationIP, packetData.sourcePort, packetData.destinationPort, packetData.layer4Protocol, packetData.tcpFlag, packetData.tlsVersion).Inc()
	}
}

func NewTTLMap(config Config) (m *TTLMap) {
	m = &TTLMap{m: make(map[string]*metric)}
	go func() {
		for now := range time.Tick(time.Second * time.Duration(config.PROMETHEUS_OUTPUT.PROMETHEUS_EXPIRATION_INTERVAL)) {
			log.Println("Running cleanup routine")
			m.l.Lock()
			totalItemsCount := 0
			totalItemsExpired := 0
			for k, v := range m.m {
				totalItemsCount++
				if now.Unix()-v.lastAccess > config.PROMETHEUS_OUTPUT.PROMETHEUS_EXPIRE_AFTER {
					totalItemsExpired++
					labels := makePacketDataFromKey(k)
					PrometheusMetricGeneric.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], labels[4], labels[5], labels[6], labels[7], labels[8])
					PrometheusMetricIncoming.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], labels[4], labels[5], labels[6], labels[7], labels[8])
					PrometheusMetricOutgoing.DeleteLabelValues(labels[0], labels[1], labels[2], labels[3], labels[4], labels[5], labels[6], labels[7], labels[8])
					delete(m.m, k)
				}
			}
			m.l.Unlock()
			log.Println("Cleanup routine finished")
			log.Printf("Number of metrics expired: %v", totalItemsExpired)
			log.Printf("New metric map size: %v", totalItemsCount-totalItemsExpired)
		}
	}()
	return
}

func (m *TTLMap) TTLMapLen() int {
	return len(m.m)
}

func (m *TTLMap) TTLMapPut(k string) {
	m.l.Lock()
	it, ok := m.m[k]
	if !ok {
		it = &metric{}
		m.m[k] = it
	}
	it.lastAccess = time.Now().Unix()
	m.l.Unlock()
}

func (m *TTLMap) TTLMapGet(k string) {
	m.l.Lock()
	if it, ok := m.m[k]; ok {
		it.lastAccess = time.Now().Unix()
	}
	m.l.Unlock()
	return

}

func makeKeyFromPacketData(packetData PacketData) string {
	result := packetData.sourceMAC
	result += "," + packetData.destinationMAC
	result += "," + packetData.sourceIP
	result += "," + packetData.destinationIP
	result += "," + packetData.sourcePort
	result += "," + packetData.destinationPort
	result += "," + packetData.layer4Protocol
	result += "," + packetData.tcpFlag
	result += "," + packetData.tlsVersion
	return result
}

func makePacketDataFromKey(key string) []string {
	return strings.Split(key, ",")
}
