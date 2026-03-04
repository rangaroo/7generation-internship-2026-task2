package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rangaroo/7generation-internship-2026-task2/internal/packet"
)

func main() {
	iface := flag.String("i", "eth0", "network interface")
	host := flag.String("ip", "", "IP address to filter")
	analyzerAddr := flag.String("addr", "localhost:9000", "analyzer address")

	flag.Parse()

	/*
		if *host == "" {
			log.Fatal("filter IP is required: -ip <IP_ADDRESS>")
		}
	*/

	// connect to analyzer on a <analyzerAddr>
	conn, err := net.Dial("tcp", *analyzerAddr)
	if err != nil {
		log.Fatalf("failed to connect to analyzer: %v", err)
	}
	defer conn.Close()

	// open pcap handle
	handle, err := pcap.OpenLive(*iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open interface: %v", err)
	}

	if *host != "" {
		// set BPF filter
		filter := fmt.Sprintf("host %s", *host)
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("failed to set BPF filter: %v", err)
		}
	}

	fmt.Printf("Collecting packets from %s, filter: %s\n", *iface, *host)

	encoder := json.NewEncoder(conn)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for p := range packetSource.Packets() {
		info := extractPacketInfo(p)
		if info == nil {
			continue
		}

		if err := encoder.Encode(info); err != nil {
			log.Printf("failed to send packet info: %v", err)
		}
	}
}

func extractPacketInfo(p gopacket.Packet) *packet.PacketFeatures {
	info := packet.PacketFeatures{}

	// get ip layer
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	info.SrcIP = ip.SrcIP.String()
	info.DstIP = ip.DstIP.String()
	info.Length = len(p.Data())

	// get transport layer
	if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.Protocol = "TCP"
	} else if udpLayer := p.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Protocol = "UDP"
	} else {
		info.Protocol = "OTHER"
	}

	return &info
}
