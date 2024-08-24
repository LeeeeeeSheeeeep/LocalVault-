package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	multicastAddr = "224.0.0.251:8765" // Custom mDNS multicast group & port to prevent OS conflicts
	maxPacketSize = 1024
)

// Peer represents a discovered sync node on the local network
type Peer struct {
	ID        string
	IP        net.IP
	SyncPort  int
	LastSeen  time.Time
}

// DiscoveryEngine handles UDP multicast beacons to discover other peers in LAN
type DiscoveryEngine struct {
	nodeID     string
	syncPort   int
	peers      map[string]*Peer
	peersMutex sync.RWMutex
	udpConn    *net.UDPConn
}

func NewDiscoveryEngine(nodeID string, syncPort int) *DiscoveryEngine {
	return &DiscoveryEngine{
		nodeID:   nodeID,
		syncPort: syncPort,
		peers:    make(map[string]*Peer),
	}
}

// GetPeers returns a list of active discovered peers
func (de *DiscoveryEngine) GetPeers() []Peer {
	de.peersMutex.RLock()
	defer de.peersMutex.RUnlock()

	var list []Peer
	for _, p := range de.peers {
		// Peer is active if seen within the last 30 seconds
		if time.Since(p.LastSeen) < 30*time.Second {
			list = append(list, *p)
		}
	}
	return list
}

// Start listens for incoming beacons and periodically broadcasts our own beacon
func (de *DiscoveryEngine) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	// 1. Setup UDP multicast listener
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on multicast UDP: %w", err)
	}
	de.udpConn = conn

	// 2. Start listener goroutine
	go de.listenLoop(ctx)

	// 3. Start broadcast loop
	go de.broadcastLoop(ctx, addr)

	return nil
}

func (de *DiscoveryEngine) Stop() error {
	if de.udpConn != nil {
		return de.udpConn.Close()
	}
	return nil
}

// broadcastLoop sends UDP beacons every 5 seconds
func (de *DiscoveryEngine) broadcastLoop(ctx context.Context, destAddr *net.UDPAddr) {
	// Create dialer socket for broadcasting
	sendConn, err := net.DialUDP("udp4", nil, destAddr)
	if err != nil {
		fmt.Printf("[Discovery] Failed to setup broadcast sender socket: %v\n", err)
		return
	}
	defer sendConn.Close()

	beaconMsg := fmt.Sprintf("LOCALVAULT_BEACON:%s:%d", de.nodeID, de.syncPort)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := sendConn.Write([]byte(beaconMsg))
			if err != nil {
				// Interface changes can cause write errors, silently log
				continue
			}
		}
	}
}

// listenLoop reads incoming multicast UDP beacons
func (de *DiscoveryEngine) listenLoop(ctx context.Context) {
	buf := make([]byte, maxPacketSize)
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, srcAddr, err := de.udpConn.ReadFromUDP(buf)
		if err != nil {
			// Socked closed on Stop()
			return
		}

		msg := string(buf[:n])
		if !strings.HasPrefix(msg, "LOCALVAULT_BEACON:") {
			continue
		}

		parts := strings.Split(msg, ":")
		if len(parts) != 3 {
			continue
		}

		peerID := parts[1]
		// Skip our own broadcasts
		if peerID == de.nodeID {
			continue
		}

		var port int
		_, err = fmt.Sscanf(parts[2], "%d", &port)
		if err != nil {
			continue
		}

		de.peersMutex.Lock()
		de.peers[peerID] = &Peer{
			ID:       peerID,
			IP:       srcAddr.IP,
			SyncPort: port,
			LastSeen: time.Now(),
		}
		de.peersMutex.Unlock()
	}
}
