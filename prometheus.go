package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
