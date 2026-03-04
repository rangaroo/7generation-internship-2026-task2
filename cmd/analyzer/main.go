package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

type Stats struct {
	mu           sync.RWMutex
	TotalPackets int            `json:"total_packets"`
	TotalBytes   int            `json:"total_bytes:"`
	ByProtocol   map[string]int `json:"by_protocol"`
	ByPort       map[uint16]int `json:"by_port"`
}

var stats = &Stats{
	ByProtocol: make(map[string]int),
	ByPort:     make(map[uint16]int),
}

func main() {
	// start tcp server for get data from sniffer
	go startTCPServer(":9000")

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

}

func statsHandler(w http.ResponseWriter, r *http.Request) {

}
