package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Key struct {
    src, dst string
}

var IPMetrics = map[Key]string{}

func startPrometheus() {

	// Expose /metrics HTTP endpoint using the created custom registry.
	go func(){
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()
	
}

func logIP (string SrcIP, string DstIP) {
	IPMetrics[Key{"2", "2"}] = "4"
	
	fmt.Println("2^2 = ", IPMetrics[Key{"2", "3"}])
}

