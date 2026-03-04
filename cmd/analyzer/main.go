package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rangaroo/7generation-internship-2026-task2/internal/packet"
)

type Stats struct {
	mu           sync.RWMutex
	TotalPackets int                   `json:"total_packets"`
	TotalBytes   int                   `json:"total_bytes:"`
	ByProtocol   map[string]int        `json:"by_protocol"`
	ByPort       map[uint16]int        `json:"by_port"`
	ByIP         map[string]*HostStats `json:"by_ip"`
}

type HostStats struct {
	Packets int `json:"packets"`
	Bytes   int `json:"bytes"`
}

var stats = &Stats{
	ByProtocol: make(map[string]int),
	ByPort:     make(map[uint16]int),
	ByIP:       make(map[string]*HostStats),
}

func main() {
	// start tcp server for get data from sniffer
	go startTCPServer(":9000")

	go printTopIPs(5 * time.Second)

	// start http server for stats endpoint
	http.HandleFunc("/stats", statsHandler)
	fmt.Println("HTTP server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func startTCPServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to start TCP server: %v", err)
	}
	fmt.Println("TCP server listening on", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		var p packet.PacketFeatures
		if err := json.Unmarshal(scanner.Bytes(), &p); err != nil {
			log.Printf("decode error: %v", err)
			continue
		}
		updateStats(&p)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats.mu.RLock()
	defer stats.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func updateStats(p *packet.PacketFeatures) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.TotalPackets++
	stats.TotalBytes += p.Length
	stats.ByProtocol[p.Protocol]++
	stats.ByPort[p.DstPort]++

	if stats.ByIP[p.SrcIP] == nil {
		stats.ByIP[p.SrcIP] = &HostStats{}
	}

	stats.ByIP[p.SrcIP].Packets++
	stats.ByIP[p.SrcIP].Bytes += p.Length
}

func findTopIPs() (topPacketsIP, topBytesIP string) {
	stats.mu.RLock()
	defer stats.mu.RUnlock()

	var maxPackets, maxBytes int

	for ip, hostStats := range stats.ByIP {
		if hostStats.Packets > maxPackets {
			maxPackets = hostStats.Packets
			topPacketsIP = ip
		}
		if hostStats.Bytes > maxBytes {
			maxBytes = hostStats.Bytes
			topBytesIP = ip
		}
	}

	return topPacketsIP, topBytesIP
}

func printTopIPs(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		topPacketsIP, topBytesIP := findTopIPs()

		fmt.Printf("\n--- Statistics ---\n")
		fmt.Printf("Top IP by packets: %s\n", topPacketsIP)
		fmt.Printf("Top IP by bytes: %s\n", topBytesIP)
		fmt.Printf("--------------------\n\n")
	}
}
