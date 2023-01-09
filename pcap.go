package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketData struct {
	sourceMAC       string
	destinationMAC  string
	sourceIP        string
	destinationIP   string
	sourcePort      string
	destinationPort string
	layer4Protocol  string
	tcpFlag         string
	tlsVersion      string
}

func pcapStart() {
	defer util.Run()()

	if *local_mac_address == "" {
		localMAC = localAddresses()
	} else {
		localMAC = *local_mac_address
	}

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

	var byteCount int64
	start := time.Now()

loop:
	for {
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
		packetData := PacketData{tlsVersion: "None"}
		for _, typ := range decoded {
			if typ == layers.LayerTypeEthernet {
				packetData.sourceMAC = eth.SrcMAC.String()
				packetData.destinationMAC = eth.DstMAC.String()
				continue
			}
			if typ == layers.LayerTypeIPv4 {
				packetData.sourceIP = ip4.SrcIP.String()
				packetData.destinationIP = ip4.DstIP.String()
				continue
			}
			if typ == layers.LayerTypeIPv6 {
				packetData.sourceIP = ip6.SrcIP.String()
				packetData.destinationIP = ip6.DstIP.String()
				continue
			}
			if typ == layers.LayerTypeTCP {
				if tcp.SYN {
					packetData.tcpFlag = "SYN"
				} else if tcp.ACK {
					packetData.tcpFlag = "ACK"
				} else if tcp.FIN {
					packetData.tcpFlag = "FIN"
				} else if tcp.RST {
					packetData.tcpFlag = "RST"
				} else if tcp.PSH {
					packetData.tcpFlag = "PSH"
				} else if tcp.URG {
					packetData.tcpFlag = "URG"
				} else if tcp.ECE {
					packetData.tcpFlag = "ECE"
				} else if tcp.CWR {
					packetData.tcpFlag = "CWR"
				} else if tcp.NS {
					packetData.tcpFlag = "NS"
				} else {
					packetData.tcpFlag = "nil"
				}
				packetData.sourcePort = tcp.SrcPort.String()
				packetData.destinationPort = tcp.DstPort.String()
				packetData.layer4Protocol = "TCP"
				continue
			}
			if typ == layers.LayerTypeUDP {
				packetData.sourcePort = udp.SrcPort.String()
				packetData.destinationPort = udp.DstPort.String()
				packetData.layer4Protocol = "UDP"
				continue
			}
			if typ == layers.LayerTypeTLS {
				if len(tls.AppData) > 0 {
					packetData.tlsVersion = tls.AppData[0].Version.String()
				}
				continue
			}
		}
		postPromethetheusMetric(packetData)
		continue loop
	}
	log.Printf("processed %d bytes in %v", byteCount, time.Since(start))
}

func localAddresses() string {
	networkInterfaces, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Printf("localAddresses: %+v\n", err.Error())
		return ""
	}
	return networkInterfaces.HardwareAddr.String()
}
