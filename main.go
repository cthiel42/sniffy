package main

import (
	"flag"
	"log"
	// "github.com/spf13/viper"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet. This will generate a significant number of logs and should only be used for debugging")
var flushAfter = flag.String("flush_after", "10s", `
Connections which have buffered packets (they've gotten packets out of order and
are waiting for old packets to fill the gaps) are flushed after they're this old
(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
acceptable here`)
var prometheus_expire_after = flag.Int64("prometheus_expire_after", 20, "After how many seconds of not seeing a metric be updated should that metric be expired and no longer reported. This is a critical configuration for cardinality issues. Expire more frequently if cardinality becomes an issue in the exporter.")
var prometheus_expiration_interval = flag.Int("prometheus_expiration_interval", 5, "How often in seconds the routine that expires metrics should be run")
var local_mac_address = flag.String("local_mac_address", "", "MAC address to consider as being the local machine for incoming and outgoing packet counter metrics")

// type Config struct {
// 	iface                          string `mapstructure:"INTERFACE"`
// 	snaplen                        int    `mapstructure:"SNAP_LEN"`
// 	logAllPackets                  bool   `mapstructure:"LOG_ALL_PACKETS"`
// 	flushAfter                     string `mapstructure:"FLUSH_AFTER"`
// 	prometheus_expire_after        int64  `mapstructure:"PROMETHEUS_EXPIRE_AFTER"`
// 	prometheus_expiration_interval int    `mapstructure:"PROMETHEUS_EXPIRATION_INTERVAL"`
// 	local_mac_address              string `mapstructure:"LOCAL_MAC_ADDRESS"`
// }

func main() {
	log.Println("Loading Config")
	//config, err := LoadConfig()

	log.Println("Starting Capture Process")
	startPrometheus()
	pcapStart()
}

// func LoadConfig(path string) (config Config, err error) {
// 	viper.AddConfigPath(path)
// 	viper.SetConfigName("app")
// 	viper.SetConfigType("env")

// 	viper.AutomaticEnv()

// 	err = viper.ReadInConfig()
// 	if err != nil {
// 		return
// 	}

// 	err = viper.Unmarshal(&config)
// 	return
// }
