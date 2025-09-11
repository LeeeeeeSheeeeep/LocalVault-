package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"localvault-sync/crypto"
	"localvault-sync/discovery"
	merklesync "localvault-sync/sync"

	_ "modernc.org/sqlite"
)

type Config struct {
	NodeID       string
	Port         int
	SyncPassword string
	DBPath       string
}

type SyncServer struct {
	cfg        Config
	db         *sql.DB
	discovery  *discovery.DiscoveryEngine
	syncActive bool
	syncMutex  sync.Mutex
}

type NetworkDoc struct {
	ID         string                 `json:"id"`
	ProviderID string                 `json:"provider_id"`
	SourceID   string                 `json:"source_id"`
	DocType    string                 `json:"doc_type"`
	Title      string                 `json:"title"`
	Content    string                 `json:"content"`
	RawData    map[string]interface{} `json:"raw_data"`
	URL        string                 `json:"url"`
	Author     string                 `json:"author"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.NodeID, "id", "sync-node-0", "Unique P2P node identifier")
	flag.IntVar(&cfg.Port, "port", 8090, "TCP port for synchronization daemon")
	flag.StringVar(&cfg.SyncPassword, "password", "syncsecret", "Handshake secure credential password")
	flag.StringVar(&cfg.DBPath, "db", "../LocalVault/data/localvault.db", "Path to target SQLite database")
	flag.Parse()

	// Ensure SQLite database dir exists
	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		log.Fatalf("[Server] Failed to open SQLite database: %v", err)
	}
	defer db.Close()

	// Quick check of database connectivity
	var tableCount int
	err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='documents'").Scan(&tableCount)
	if err != nil || tableCount == 0 {
		log.Printf("[Warning] SQLite documents table does not exist yet at %s. Waiting for LocalVault backend to initialize it first.", cfg.DBPath)
	}

	de := discovery.NewDiscoveryEngine(cfg.NodeID, cfg.Port)
	ss := &SyncServer{
		cfg:       cfg,
		db:        db,
		discovery: de,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start discovery engine (multicast UDP beacons)
	if err := de.Start(ctx); err != nil {
		log.Printf("[Discovery] Failed to start multicast engine: %v", err)
	} else {
		log.Println("[Discovery] Local UDP multicast network node discovery started.")
	}
	defer de.Stop()

	// 2. Start P2P TCP Server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatalf("[Server] Failed to start TCP listener: %v", err)
	}
	defer listener.Close()
	log.Printf("[Server] Zero-Knowledge P2P Sync Daemon running on TCP port %d\n", cfg.Port)

	go ss.acceptConnections(listener)

	// 3. Periodically trigger peer client checks (every 15 seconds)
	go ss.peerScannerLoop(ctx)

	// Keep main alive until termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[Daemon] Shutting down P2P sync daemon.")
}

func (ss *SyncServer) acceptConnections(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go ss.handleConnection(conn)
	}
}

// handleConnection performs handshake and processes synchronization requests
func (ss *SyncServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Set handshake timeout
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Secure handshake
	session, err := crypto.CompleteHandshake(conn, ss.cfg.SyncPassword)
	if err != nil {
		log.Printf("[Handshake] Authentication failed with %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[Handshake] Session successfully secured with %s (AES-GCM-256)", conn.RemoteAddr())
	
	// Handshake done: remove timeout for protocol loop
	conn.SetDeadline(time.Time{})

	// 2. Protocol Loop: Receive or Exchange Merkle Sync Request
	ss.runSyncProtocol(conn, session)
}

func (ss *SyncServer) runSyncProtocol(conn net.Conn, sess *crypto.Session) {
	ss.syncMutex.Lock()
	defer ss.syncMutex.Unlock()

	// Fetch local metadata
	localDocs, err := ss.getLocalMetadata()
	if err != nil {
		log.Printf("[Protocol] Failed to read local records metadata: %v", err)
		return
	}

	// Build local Merkle Tree
	localTree := merklesync.BuildMerkleTree(localDocs)

	// Encode and send root hash to remote peer
	reqPayload := map[string]interface{}{
		"node_id":   ss.cfg.NodeID,
		"root_hash": hex.EncodeToString(localTree.Hash),
	}
	reqBytes, _ := json.Marshal(reqPayload)
	encReq, err := sess.Encrypt(reqBytes)
	if err != nil {
		return
	}

	if err := merklesync.WriteFrame(conn, encReq); err != nil {
		return
	}

	// Read peer's root hash
	encRes, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	resBytes, err := sess.Decrypt(encRes)
	if err != nil {
		return
	}

	var peerRes struct {
		NodeID   string `json:"node_id"`
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(resBytes, &peerRes); err != nil {
		return
	}

	log.Printf("[Sync] Comparing hash trees with peer %s (root: %s)", peerRes.NodeID, peerRes.RootHash)

	// If root hashes match, databases are identical
	if peerRes.RootHash == hex.EncodeToString(localTree.Hash) {
		log.Printf("[Sync] Vaults are in perfect sync with %s. No data exchange required.", peerRes.NodeID)
		return
	}

	// 3. Merkle Diff Engine: Request Merkle Leaves list from remote peer
	reqDiffMsg, _ := json.Marshal(map[string]string{"cmd": "GET_LEAVES"})
	encDiffReq, _ := sess.Encrypt(reqDiffMsg)
	merklesync.WriteFrame(conn, encDiffReq)

	// Read peer Merkle leaf hashes
	encLeafRes, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	leafBytes, err := sess.Decrypt(encLeafRes)
	if err != nil {
		return
	}

	var peerLeaves []merklesync.DocMetadata
	if err := json.Unmarshal(leafBytes, &peerLeaves); err != nil {
		return
	}

	// Rebuild peer local Merkle Tree from its leaf list to compare differences
	peerTree := merklesync.BuildMerkleTree(peerLeaves)
	outOfSyncIDs := merklesync.CompareMerkleTrees(localTree, peerTree)

	if len(outOfSyncIDs) == 0 {
		log.Println("[Sync] Merkle trees structures match but root hashes differed (hash collision or empty nodes).")
		return
	}

	log.Printf("[Sync] Isolated %d document differences. Resolving sync paths.", len(outOfSyncIDs))

	// For each difference, swap timestamps to decide whether to push, pull or ignore
	peerMetadataMap := make(map[string]merklesync.DocMetadata)
	for _, l := range peerLeaves {
		peerMetadataMap[l.ID] = l
	}

	var requestDocIDs []string
	var sendDocs []NetworkDoc

	for _, id := range outOfSyncIDs {
		localMeta, hasLocal := findDocMeta(localDocs, id)
		peerMeta, hasPeer := peerMetadataMap[id]

		if hasLocal && !hasPeer {
			// We have it, they don't: Send it
			doc, err := ss.getDocument(id)
			if err == nil {
				sendDocs = append(sendDocs, *doc)
			}
		} else if !hasLocal && hasPeer {
			// They have it, we don't: Request it
			requestDocIDs = append(requestDocIDs, id)
		} else if hasLocal && hasPeer {
			// Both have it: compare timestamps
			if localMeta.UpdatedAt.After(peerMeta.UpdatedAt) {
				doc, err := ss.getDocument(id)
				if err == nil {
					sendDocs = append(sendDocs, *doc)
				}
			} else if localMeta.UpdatedAt.Before(peerMeta.UpdatedAt) {
				requestDocIDs = append(requestDocIDs, id)
			}
		}
	}

	// Send delta exchange packet containing:
	// - Raw document structures we are pushing
	// - List of document IDs we are pulling
	exchangePayload := map[string]interface{}{
		"push": sendDocs,
		"pull": requestDocIDs,
	}
	exchBytes, _ := json.Marshal(exchangePayload)
	encExch, _ := sess.Encrypt(exchBytes)
	merklesync.WriteFrame(conn, encExch)

	// Read peer delta packet (their push data for the records we requested)
	encPeerExch, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	peerExchBytes, err := sess.Decrypt(encPeerExch)
	if err != nil {
		return
	}

	var peerExchange struct {
		Push []NetworkDoc `json:"push"`
	}
	if err := json.Unmarshal(peerExchBytes, &peerExchange); err != nil {
		return
	}

	// Save incoming documents to our local store
	savedCount := 0
	for _, doc := range peerExchange.Push {
		err := ss.saveDocument(&doc)
		if err == nil {
			savedCount++
		}
	}

	log.Printf("[Sync] Synchronization completed. Received %d records, Sent %d records.", savedCount, len(sendDocs))
}

func (ss *SyncServer) peerScannerLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers := ss.discovery.GetPeers()
			for _, peer := range peers {
				go ss.syncWithPeer(peer)
			}
		}
	}
}

// syncWithPeer acts as the client initiator node
func (ss *SyncServer) syncWithPeer(peer discovery.Peer) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", peer.IP, peer.SyncPort), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 1. Handshake
	session, err := crypto.CompleteHandshake(conn, ss.cfg.SyncPassword)
	if err != nil {
		return
	}

	// 2. Perform sync protocol
	ss.syncMutex.Lock()
	defer ss.syncMutex.Unlock()

	// Fetch local metadata
	localDocs, err := ss.getLocalMetadata()
	if err != nil {
		return
	}
	localTree := merklesync.BuildMerkleTree(localDocs)

	// Read peer request root hash frame
	encReq, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	reqBytes, err := session.Decrypt(encReq)
	if err != nil {
		return
	}

	var peerReq struct {
		NodeID   string `json:"node_id"`
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(reqBytes, &peerReq); err != nil {
		return
	}

	// Send our root hash
	resPayload := map[string]interface{}{
		"node_id":   ss.cfg.NodeID,
		"root_hash": hex.EncodeToString(localTree.Hash),
	}
	resBytes, _ := json.Marshal(resPayload)
	encRes, _ := session.Encrypt(resBytes)
	merklesync.WriteFrame(conn, encRes)

	// If hashes match, exit
	if peerReq.RootHash == hex.EncodeToString(localTree.Hash) {
		return
	}

	// Read peer leaf request
	encDiffReq, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	diffReqBytes, err := session.Decrypt(encDiffReq)
	if err != nil {
		return
	}

	var cmdMsg map[string]string
	json.Unmarshal(diffReqBytes, &cmdMsg)

	if cmdMsg["cmd"] == "GET_LEAVES" {
		// Send our local leaves list
		leavesBytes, _ := json.Marshal(localDocs)
		encLeaves, _ := session.Encrypt(leavesBytes)
		merklesync.WriteFrame(conn, encLeaves)
	} else {
		return
	}

	// Read peer exchange frame
	encPeerExch, err := merklesync.ReadFrame(conn)
	if err != nil {
		return
	}
	peerExchBytes, err := session.Decrypt(encPeerExch)
	if err != nil {
		return
	}

	var peerExch struct {
		Push []NetworkDoc `json:"push"`
		Pull []string     `json:"pull"`
	}
	if err := json.Unmarshal(peerExchBytes, &peerExch); err != nil {
		return
	}

	// Save documents peer pushed to us
	for _, doc := range peerExch.Push {
		ss.saveDocument(&doc)
	}

	// Compile the list of documents peer requested from us
	var pushDocs []NetworkDoc
	for _, id := range peerExch.Pull {
		doc, err := ss.getDocument(id)
		if err == nil {
			pushDocs = append(pushDocs, *doc)
		}
	}

	// Send our push response
	responsePayload := map[string]interface{}{
		"push": pushDocs,
	}
	respBytes, _ := json.Marshal(responsePayload)
	encResp, _ := session.Encrypt(respBytes)
	merklesync.WriteFrame(conn, encResp)
}

// Database Helper Methods

func (ss *SyncServer) getLocalMetadata() ([]merklesync.DocMetadata, error) {
	// Query FTS document references
	query := `SELECT id, title, content, updated_at FROM documents`
	rows, err := ss.db.Query(query)
	if err != nil {
		// Return empty list if table doesn't exist yet
		return []merklesync.DocMetadata{}, nil
	}
	defer rows.Close()

	var list []merklesync.DocMetadata
	for rows.Next() {
		var id, title, content string
		var updatedAt time.Time
		if err := rows.Scan(&id, &title, &content, &updatedAt); err != nil {
			return nil, err
		}

		// Compute content hash
		hasher := sha256.New()
		hasher.Write([]byte(title + content))
		docHash := hex.EncodeToString(hasher.Sum(nil))

		list = append(list, merklesync.DocMetadata{
			ID:        id,
			Hash:      docHash,
			UpdatedAt: updatedAt,
		})
	}
	return list, nil
}

func (ss *SyncServer) getDocument(id string) (*NetworkDoc, error) {
	query := `
		SELECT id, provider_id, source_id, doc_type, title, content, raw_data, url, author, created_at, updated_at
		FROM documents WHERE id = ?
	`
	var doc NetworkDoc
	var rawJSON string
	err := ss.db.QueryRow(query, id).Scan(
		&doc.ID, &doc.ProviderID, &doc.SourceID, &doc.DocType,
		&doc.Title, &doc.Content, &rawJSON, &doc.URL, &doc.Author,
		&doc.CreatedAt, &doc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if rawJSON != "" {
		json.Unmarshal([]byte(rawJSON), &doc.RawData)
	}
	return &doc, nil
}

func (ss *SyncServer) saveDocument(doc *NetworkDoc) error {
	rawJSON, err := json.Marshal(doc.RawData)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO documents (id, provider_id, source_id, doc_type, title, content, raw_data, url, author, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title=excluded.title,
			content=excluded.content,
			raw_data=excluded.raw_data,
			updated_at=excluded.updated_at
	`
	_, err = ss.db.Exec(query,
		doc.ID, doc.ProviderID, doc.SourceID, doc.DocType,
		doc.Title, doc.Content, string(rawJSON), doc.URL, doc.Author,
		doc.CreatedAt, doc.UpdatedAt,
	)
	return err
}

func findDocMeta(list []merklesync.DocMetadata, id string) (merklesync.DocMetadata, bool) {
	for _, m := range list {
		if m.ID == id {
			return m, true
		}
	}
	return merklesync.DocMetadata{}, false
}
