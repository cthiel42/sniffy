package sniffy

import (
	"flag"
	"github.com/spf13/viper"
	"log"
)

var configPath = flag.String("config", "configs/config.yaml", "path to config file")

type PCAP_INPUT struct {
	INTERFACE_NAME    string `yaml:"interface_name"`
	SNAP_LEN          int    `yaml:"snap_len"`
	LOG_ALL_PACKETS   bool   `yaml:"log_all_packets"`
	FLUSH_AFTER       string `yaml:"flush_after"`
	LOCAL_MAC_ADDRESS string `yaml:"local_mac_address"`
}

type PROMETHEUS_OUTPUT struct {
	ENABLED                        bool     `yaml:"enabled"`
	PROMETHEUS_EXPIRE_AFTER        int64    `yaml:"prometheus_expire_after"`
	PROMETHEUS_EXPIRATION_INTERVAL int      `yaml:"prometheus_expiration_interval"`
	PROMETHEUS_METRICS_PORT        int      `yaml:"prometheus_metrics_port"`
	PROMETHEUS_EXCLUDE_FIELDS      []string `yaml:"prometheus_exclude_fields"`
}

type Config struct {
	PCAP_INPUT        PCAP_INPUT        `yaml:"pcap_input"`
	PROMETHEUS_OUTPUT PROMETHEUS_OUTPUT `yaml:"prometheus_output"`
}

func Start() {
	log.Println("Loading Config")

	config, err := LoadConfig()
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Starting Capture Process")
	if config.PROMETHEUS_OUTPUT.ENABLED {
		startPrometheus(config)
	} else {
		log.Println("No output specified. Exiting")
		return
	}

	pcapStart(config)
}

func LoadConfig() (config Config, err error) {
	viper.SetConfigFile(*configPath)

	err = viper.ReadInConfig()
	if err != nil {
		return
	}
	viper.SetDefault("PCAP_INPUT.interface_name", "eth0")
	viper.SetDefault("PCAP_INPUT.snap_len", 65536)
	viper.SetDefault("PCAP_INPUT.log_all_packets", false)
	viper.SetDefault("PCAP_INPUT.flush_after", "10s")
	viper.SetDefault("PCAP_INPUT.local_mac_address", "")
	viper.SetDefault("PROMETHEUS_OUTPUT.enabled", true)
	viper.SetDefault("PROMETHEUS_OUTPUT.prometheus_expire_after", 900)
	viper.SetDefault("PROMETHEUS_OUTPUT.prometheus_expiration_interval", 60)
	viper.SetDefault("PROMETHEUS_OUTPUT.prometheus_metrics_port", 8080)
	viper.SetDefault("PROMETHEUS_OUTPUT.prometheus_exclude_fields", []string{})

	err = viper.Unmarshal(&config)
	return
}

func init() {
	flag.Parse()
}
