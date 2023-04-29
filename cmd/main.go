package main

import (
	"encoding/json"
	"io"
	"log"

	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	//"github.com/ReneKroon/ttlcache"
	ct "github.com/florianl/go-conntrack"
	"github.com/gin-gonic/gin"
	"github.com/penglongli/gin-metrics/ginmetrics"
	//"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Connection struct {
	ID              uint64 `json:"id"`
	Duration        int64  `json:"duration"`
	LastEvent       int64  `json:"last_event"`
	Status          string `json:"status"`
	Start           int64  `json:"start"`
	Source          net.IP `json:"src"`
	Destination     net.IP `json:"dst"`
	SourcePort      uint16 `json:"sport"`
	DestinationPort uint16 `json:"dport"`
	Proto           string `json:"proto"`
}

var (
	mutex       = &sync.RWMutex{}
	connections = map[uint64]*Connection{}

	countConnections = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "conntrack_connection_count",
		Help: "Currently active connections on this host",
	}, []string{
		"state",
	})

	histogramConnectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "conntrack_connection_duration_seconds",
		Help:    "Observed duration of a connection",
		Buckets: prometheus.ExponentialBuckets(0.001, 5, 10),
	})

	tcpStates = map[uint8]string{
		0:  "INVALID",
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
	}
)

// It keeps a list of clients those are currently attached
// and broadcasting events to those clients.
type Event struct {
	// Events are pushed to this channel by the main events-gathering routine
	Message chan string

	// New client connections
	NewClients chan chan string

	// Closed client connections
	ClosedClients chan chan string

	// Total client connections
	TotalClients map[chan string]bool
}

type ClientChan chan string

// Initialize event and Start procnteessing requests
func NewServer() (event *Event) {
	event = &Event{
		Message:       make(chan string),
		NewClients:    make(chan chan string),
		ClosedClients: make(chan chan string),
		TotalClients:  make(map[chan string]bool),
	}

	go event.listen()

	return
}

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func (stream *Event) listen() {
	for {
		select {
		// Add new available client
		case client := <-stream.NewClients:
			stream.TotalClients[client] = true
			log.Printf("Client added. %d registered clients", len(stream.TotalClients))

		// Remove closed client
		case client := <-stream.ClosedClients:
			delete(stream.TotalClients, client)
			close(client)
			log.Printf("Removed client. %d registered clients", len(stream.TotalClients))

		// Broadcast message to client
		case eventMsg := <-stream.Message:
			for clientMessageChan := range stream.TotalClients {
				clientMessageChan <- eventMsg
			}
		}
	}
}

func (stream *Event) serveHTTP() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Initialize client channel
		clientChan := make(ClientChan)

		// Send new connection to event server
		stream.NewClients <- clientChan

		defer func() {
			// Send closed connection to event server
			stream.ClosedClients <- clientChan
		}()

		c.Set("clientChan", clientChan)

		c.Next()
	}
}

func HeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Next()
	}
}

func DecodeProtoState(pi *ct.ProtoInfo) string {
	if pi != nil && pi.TCP != nil {
		return tcpStates[*pi.TCP.State]
	} else {
		return "UNKNOWN"
	}
}

func DecodeState(state uint32) string {
	// https://cs.android.com/android/platform/superproject/+/master:frameworks/libs/net/common/device/com/android/net/module/util/netlink/ConntrackMessage.java;drc=58806f9bcbad4338983d026db0a4390af8d4a7e2;l=313

	if state&(1<<12) != 0 {
		return "untracked"
	}
	if state&(1<<10) != 0 {
		return "fixed_timeout"
	}

	if state&(1<<9) != 0 {
		return "dying"
	}

	if state&(1<<3) != 0 {
		return "confirmed"
	}

	if state&(1<<2) != 0 {
		return "assured"
	}

	if state&(1<<1) != 0 {
		return "reply_seen"
	}

	if state&(1<<0) != 0 {
		return "expected"
	}
	return "unknown"
}

func main() {

	nfct, err := ct.Open(&ct.Config{})

	if err != nil {
		fmt.Println("could not create nfct:", err)
		return
	}
	defer nfct.Close()
	stream := NewServer()
	protocols := map[uint8]string{
		1:  "ICMP",
		2:  "IGMP",
		6:  "TCP",
		17: "UDP",
	}

	monitor := func(c ct.Con) int {

		if c.Origin.Src.String() == "127.0.0.1" {
			return 0
		}

		sport := uint16(0)
		dport := uint16(0)

		// Extract port numbers if it's TCP/UDP and not eg ICMP
		if c.Origin.Proto != nil && c.Origin.Proto.SrcPort != nil && c.Origin.Proto.DstPort != nil {
			sport = *c.Origin.Proto.SrcPort
			dport = *c.Origin.Proto.DstPort
		}

		now := time.Now().Unix()
		idnum := uint64(*c.ID)
		mutex.Lock()
		if conn, ok := connections[idnum]; ok {
			conn.LastEvent = now
			conn.Duration = now - conn.Start
			conn.Status = DecodeState(*c.Status)
			if ((*c.Status) & (1 << 9)) != 0 { // dying
				histogramConnectionDuration.Observe(float64(now - conn.Start))
				delete(connections, idnum)
				log.Printf("Connection %08x closed, state %s, total %d", c.ID, DecodeState(*c.Status), len(connections))
				bytes, _ := json.Marshal(conn)
				stream.Message <- string(bytes)
			} else {
				log.Printf("Connection %08x updated, state %s, total %d", c.ID, DecodeState(*c.Status), len(connections))
			}
		} else {
			if ((*c.Status) & (1 << 9)) == 0 {
				conn := &Connection{
					ID:              idnum,
					Start:           now,
					LastEvent:       now,
					Status:          DecodeState(*c.Status),
					Source:          *c.Origin.Src,
					Destination:     *c.Origin.Dst,
					SourcePort:      sport,
					DestinationPort: dport,
					Proto:           protocols[*c.Origin.Proto.Number],
				}
				connections[idnum] = conn
				log.Printf("Connection %08x started, state %s, total %d", c.ID, DecodeState(*c.Status), len(connections))
				bytes, _ := json.Marshal(conn)
				stream.Message <- string(bytes)
			} else {
				log.Printf("Got new untracked connection %08x, state %s, total %d", c.ID, DecodeState(*c.Status), len(connections))
			}

		}
		mutex.Unlock()
		countConnections.With(prometheus.Labels{"state": ""}).Set(float64(len(connections)))
		return 0
	}

	if err := nfct.Register(context.Background(), ct.Conntrack, ct.NetlinkCtNew|ct.NetlinkCtUpdate|ct.NetlinkCtDestroy, monitor); err != nil {
		fmt.Println("could not register callback:", err)
		return
	}

	router := gin.Default()

	metrics := ginmetrics.GetMonitor()
	metrics.SetMetricPath("/metrics")
	metrics.Use(router)

	router.GET("/stream", HeadersMiddleware(), stream.serveHTTP(), func(c *gin.Context) {
		c.SSEvent("stream-opened", "")
		v, ok := c.Get("clientChan")
		if !ok {
			return
		}
		clientChan, ok := v.(ClientChan)
		if !ok {
			return
		}
		c.Stream(func(w io.Writer) bool {
			if msg, ok := <-clientChan; ok {
				c.SSEvent("connection-update", msg)
				return true
			}
			return false
		})
	})

	router.GET("/dump", func(c *gin.Context) {
		var conns []Connection
		mutex.Lock()
		for _, element := range connections {
			conns = append(conns, *element)
		}
		mutex.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"connections": conns,
		})
	})

	router.Run(":5442")
}
