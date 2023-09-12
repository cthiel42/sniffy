# sniffy
Metric collection tool for level 3 and 4 packet analysis. Currently supports monitoring a network interface and displaying results as Prometheus metrics.
Data collected:
- MAC addresses
- Ports
- IP addresses
- Layer 4 Protocol Used
- TCP Flag
- TLS Version

JSON for a basic Grafana dashboard built off Prometheus data from Sniffy can be found under `/dashboards`. 

### Environment Setup
- Need to have Golang version 1.18+ installed
- You'll also likely need to install a package called libpcap-dev or libpcap-devel (depending on what package manager you're using) to handle a pcap.h error
- Running `go build cmd/*.go` from the root directory will build the binary, or running `go run cmd/*.go` will run the program from your terminal

### Config
The config is specified in yaml and the application by default looks for it in a configs folder within the current working directory, i.e. `configs/config.yaml`. You can override the path to the config with the command line flag `--config=\path\to\config.yaml`

For an example of the config file, look at `config.yaml`. Detailed configuration settings can be found listed below.

![Grafana Dashboard Example](https://raw.githubusercontent.com/cthiel42/sniffy/main/dashboard/Capture.JPG)

* `PCAP_INPUT` // This encompasses settings surrounding the interface packets are being captured on
  - `INTERFACE_NAME` // The interface name to capture packets on, as listed in a command such as ifconfig
  - `SNAP_LEN` // SnapLen for pcap packet capture
  - `LOG_ALL_PACKETS` // Boolean. Log whenever we see a packet. This will generate a significant number of logs and should only be used for debugging
  - `FLUSH_AFTER` // This setting currently has no effect on the application, but was implemented for use in future features. Connections which have buffered packets (they've gotten packets out of order and are waiting for old packets to fill the gaps) are flushed after they're this old (their oldest gap is skipped).  Any string parsed by time.ParseDuration is acceptable here`)
  - `LOCAL_MAC_ADDRESS` // The MAC address to consider as being the local machine for incoming and outgoing packet counter metrics. If not specified, the application will attempt to determine the local MAC address itself

* `PROMETHEUS_OUTPUT`
  - `ENABLED` // Enables the Prometheus metrics output
  - `PROMETHEUS_EXPIRATION_INTERVAL` // Specifies the interval in seconds on which the cleanup routine should run to expire stale data.
  - `PROMETHEUS_EXPIRE_AFTER` // After how many seconds of not seeing a metric be updated should that metric be expired and no longer reported. This is a critical configuration for cardinality issues. Expire more frequently if cardinality becomes an issue in the exporter.
  - `PROMETHEUS_METRICS_PORT` // Port to run the /metrics endpoint on
  - `PROMETHEUS_EXCLUDE_FIELDS` // Array of fields to exclude in metrics to reduce cardinality. Options are: `sourceMAC`, `destinationMAC`, `sourceIP`, `destinationIP`, `sourcePort`, `destinationPort`, `layer4Protocol`, `tcpFlag`, `tlsVersion`

Features to be worked on:
- Influx Output
- Create config logic to decide what input and output gets selected. Ideally like to have logging output to send both application logs and pcap logs to something like Elastic Search, Loki, or Splunk