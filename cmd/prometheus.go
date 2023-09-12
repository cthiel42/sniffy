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
var labels []string

func startPrometheus(config Config) {
	expirationMap = NewTTLMap(config)

	labelOptions := []string{"sourceMAC", "destinationMAC", "sourceIP", "destinationIP", "sourcePort", "destinationPort", "layer4Protocol", "tcpFlag", "tlsVersion"}
	for _, label := range labelOptions {
		if !contains(config.PROMETHEUS_OUTPUT.PROMETHEUS_EXCLUDE_FIELDS, label) {
			labels = append(labels, label)
		}
	}

	PrometheusMetricGeneric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_counter",
			Help: "How many packets have been seen between the given source and destination fields. This is used for packets where the source/destination can't be identified as the local machine",
		},
		labels,
	)
	prometheus.MustRegister(PrometheusMetricGeneric)

	PrometheusMetricIncoming = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "incoming_packets_counter",
			Help: "How many packets have been seen incoming from the source fields to the local machine",
		},
		labels,
	)
	prometheus.MustRegister(PrometheusMetricIncoming)

	PrometheusMetricOutgoing = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "outgoing_packets_counter",
			Help: "How many packets have been seen outgoing from the local machine to the destination fields",
		},
		labels,
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
	dynamicLabels := make(prometheus.Labels)

	// As gross as this switch statement is, the other option is to use
	// reflect, which comes with a noticeable hit to runtime performance
	// due to the need for type inference. The switch statement also
	// provides type safety
	for _, labelName := range labels {
		switch labelName {
		case "sourceMAC":
			dynamicLabels[labelName] = packetData.sourceMAC
		case "destinationMAC":
			dynamicLabels[labelName] = packetData.destinationMAC
		case "sourceIP":
			dynamicLabels[labelName] = packetData.sourceIP
		case "destinationIP":
			dynamicLabels[labelName] = packetData.destinationIP
		case "sourcePort":
			dynamicLabels[labelName] = packetData.sourcePort
		case "destinationPort":
			dynamicLabels[labelName] = packetData.destinationPort
		case "layer4Protocol":
			dynamicLabels[labelName] = packetData.layer4Protocol
		case "tcpFlag":
			dynamicLabels[labelName] = packetData.tcpFlag
		case "tlsVersion":
			dynamicLabels[labelName] = packetData.tlsVersion
		}
	}

	if localMAC == packetData.sourceMAC {
		PrometheusMetricOutgoing.With(dynamicLabels).Inc()
	} else if localMAC == packetData.destinationMAC {
		PrometheusMetricIncoming.With(dynamicLabels).Inc()
	} else {
		PrometheusMetricGeneric.With(dynamicLabels).Inc()
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
					labelsToDelete := makePacketDataFromKey(k)
					PrometheusMetricGeneric.DeleteLabelValues(labelsToDelete...)
					PrometheusMetricIncoming.DeleteLabelValues(labelsToDelete...)
					PrometheusMetricOutgoing.DeleteLabelValues(labelsToDelete...)
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
	var result strings.Builder

	// Same deal as above. Gross switch statement but has type safety and
	// a lot better performance than reflect
	for _, label := range labels {
		switch label {
		case "sourceMAC":
			result.WriteString(packetData.sourceMAC)
		case "destinationMAC":
			result.WriteString(packetData.destinationMAC)
		case "sourceIP":
			result.WriteString(packetData.sourceIP)
		case "destinationIP":
			result.WriteString(packetData.destinationIP)
		case "sourcePort":
			result.WriteString(packetData.sourcePort)
		case "destinationPort":
			result.WriteString(packetData.destinationPort)
		case "layer4Protocol":
			result.WriteString(packetData.layer4Protocol)
		case "tcpFlag":
			result.WriteString(packetData.tcpFlag)
		case "tlsVersion":
			result.WriteString(packetData.tlsVersion)
		}
	}

	return result.String()
}

func makePacketDataFromKey(key string) []string {
	return strings.Split(key, ",")
}

func contains(slice []string, element string) bool {
	for _, value := range slice {
		if value == element {
			return true
		}
	}
	return false
}
