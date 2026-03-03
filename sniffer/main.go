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

	if *host == "" {
		log.Fatal("filter IP is required: -filter <IP_ADDRESS>")
	}

	// connect to analyzer
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

	// set BPF filter
	filter := fmt.Sprintf("host %s", *host)
	if err := handle.SetBPFFilter(bpf); err != nil {
		log.Fatalf("failed to set BPF filter: %v", err)
	}

	fmt.Printf("Collecting packets from %s, filter: %s\n", *iface, *host)

	encoder := json.NewEncoder(conn)

	for packet := range packetSource.Packets() {
		info := extractPacketInfo(packet)
		if info == nil {
			continue
		}

		if err := encoder.Encode(info); err != nil {
			log.Printf("failed to send packet info: %v", err)
		}
	}
}

func extractPacketInfo(packet gopacket.Packet) *packet.PacketFeatures {
	var info packet.PacketFeatures

	// get ip layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	info.SrcIP := ip.SrcIP.String()
	info.DstIP := ip.DstIP.String()
	info.Length := len(packet.Data())

	// get transport layer

}
