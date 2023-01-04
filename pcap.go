package main

import (
	"flag"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

//var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Log whenever we see a packet. This will generate a significant number of logs and should only be used for debugging")
var flushAfter = flag.String("flush_after", "10s", `
Connections which have buffered packets (they've gotten packets out of order and
are waiting for old packets to fill the gaps) are flushed after they're this old
(their oldest gap is skipped).  Any string parsed by time.ParseDuration is
acceptable here`)

func pcapStart() {
	defer util.Run()()

	startPrometheus()

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Fatal("invalid flush duration: ", *flushAfter)
	}

	log.Printf("starting capture on interface %q", *iface)
	// Set up pcap packet capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, flushDuration/2)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	// if err := handle.SetBPFFilter(*filter); err != nil {
	// 	log.Fatal("error setting BPF filter: ", err)
	// }

	log.Println("reading in packets")

	// We use a DecodingLayerParser here instead of a simpler PacketSource.
	// This approach should be measurably faster, but is also more rigid.
	// PacketSource will handle any known type of packet safely and easily,
	// but DecodingLayerParser will only handle those packet types we
	// specifically pass in.  This trade-off can be quite useful, though, in
	// high-throughput situations.
	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var tls layers.TLS
	var payload gopacket.Payload
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &tls, &payload, &udp)
	decoded := make([]gopacket.LayerType, 0, 4)

	nextFlush := time.Now().Add(flushDuration / 2)

	var byteCount int64
	start := time.Now()

loop:
	for {
		// Check to see if we should flush the streams we have
		// that haven't seen any new data in a while.  Note we set a
		// timeout on our PCAP handle, so this should happen even if we
		// never see packet data.
		if time.Now().After(nextFlush) {
			stats, _ := handle.Stats()
			log.Println("Reporting stats: %+v", stats)
			nextFlush = time.Now().Add(flushDuration / 2)
		}

		// To speed things up, we're also using the ZeroCopy method for
		// reading packet data.  This method is faster than the normal
		// ReadPacketData, but the returned bytes in 'data' are
		// invalidated by any subsequent ZeroCopyReadPacketData call.
		// Note that tcpassembly is entirely compatible with this packet
		// reading method.  This is another trade-off which might be
		// appropriate for high-throughput sniffing:  it avoids a packet
		// copy, but its cost is much more careful handling of the
		// resulting byte slice.
		data, _, err := handle.ZeroCopyReadPacketData() // TODO: Replace underscore with ci to get another object with more information

		if err != nil {
			//log.Printf("error getting packet: %v", err) // DEBUG
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			//log.Printf("error decoding packet: %v", err) // DEBUG
			continue
		}
		if *logAllPackets {
			log.Printf("decoded the following layers: %v", decoded)
		}
		byteCount += int64(len(data))
		// Find IP addresses, ports, MAC addresses, and any other information
		// in the packet that would be relevant

		// TODO: Add IANA default ports for reporting on protocols used
		// TODO: Keep track of packet counts during a window, bytes during a window, separate sends and receives

		// log.Println(decoded) // DEBUG
		sourceMAC := ""
		destinationMAC := ""
		sourceIP := ""
		destinationIP := ""
		sourcePort := ""
		destinationPort := ""
		layer4Protocol := ""
		tcpFlag := ""
		tlsVersion := "none"
		for _, typ := range decoded {
			if typ == layers.LayerTypeEthernet {
				sourceMAC = eth.SrcMAC.String()
				destinationMAC = eth.DstMAC.String()
				continue
			}
			if typ == layers.LayerTypeIPv4 {
				sourceIP = ip4.SrcIP.String()
				destinationIP = ip4.DstIP.String()
				continue
			}
			if typ == layers.LayerTypeIPv6 {
				sourceIP = ip6.SrcIP.String()
				destinationIP = ip6.DstIP.String()
				continue
			}
			if typ == layers.LayerTypeTCP {
				if tcp.SYN {
					tcpFlag = "SYN"
				} else if tcp.ACK {
					tcpFlag = "ACK"
				} else if tcp.FIN {
					tcpFlag = "FIN"
				} else if tcp.RST {
					tcpFlag = "RST"
				} else if tcp.PSH {
					tcpFlag = "PSH"
				} else if tcp.URG {
					tcpFlag = "URG"
				} else if tcp.ECE {
					tcpFlag = "ECE"
				} else if tcp.CWR {
					tcpFlag = "CWR"
				} else if tcp.NS {
					tcpFlag = "NS"
				} else {
					tcpFlag = "nil"
				}
				sourcePort = tcp.SrcPort.String()
				destinationPort = tcp.DstPort.String()
				layer4Protocol = "TCP"
				continue
			}
			if typ == layers.LayerTypeUDP {
				sourcePort = udp.SrcPort.String()
				destinationPort = udp.DstPort.String()
				layer4Protocol = "UDP"
				continue
			}
			if typ == layers.LayerTypeTLS {
				if len(tls.AppData) > 0 {
					tlsVersion = tls.AppData[0].Version.String()
				}
				continue
			}
		}
		PrometheusMetric.WithLabelValues(sourceMAC, destinationMAC, sourceIP, destinationIP, sourcePort, destinationPort, layer4Protocol, tcpFlag, tlsVersion).Inc()
		continue loop
	}
	log.Printf("processed %d bytes in %v", byteCount, time.Since(start))
}
