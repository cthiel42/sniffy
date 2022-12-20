package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// var IPMetrics = map[string]string{}
var IPPrometheusMetric *prometheus.CounterVec

func startPrometheus() {
	IPPrometheusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_sent_by_ip_address",
			Help: "How many packets have been sent between the source and destination IP addresses.",
		},
		[]string{"source", "destination"},
	)
	prometheus.MustRegister(IPPrometheusMetric)

	// Expose /metrics HTTP endpoint using the created custom registry.
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

}

func promIP(SrcIP, DstIP string) {
	log.Println(SrcIP, DstIP)
	IPPrometheusMetric.WithLabelValues(SrcIP, DstIP).Inc()
}
