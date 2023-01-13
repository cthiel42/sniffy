# sniffy
Packet Sniffing and Analysis Tool

### Environment Setup
- Need to have Golang version 1.18+ installed
- You'll also likely need to install a package called libpcap-dev or libpcap-devel (depending on what package manager you're using) to handle a pcap.h error

### Config
The config is specified in yaml and the application by default looks for it in the current working directory by the name `config.yaml`. You can override the path to the config with the command line flag `--config=\path\to\config.yaml`

For an example of the config file, look at `config.yaml`. Detailed configuration settings can be found listed below.

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

Steps:

- Test this in the lab with a prometheus server and see what performance is like
- Create config logic to decide what input and output gets selected
- Add switches into the code to allow certain analysis and statistics to be or not be reported
