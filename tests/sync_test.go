package tests

import (
	"bytes"
	"net"
	"testing"
	"time"

	"localvault-sync/crypto"
	"localvault-sync/sync"
)

func TestMerkleTreeBuildAndCompare(t *testing.T) {
	// Identical sets
	docsA := []sync.DocMetadata{
		{ID: "doc-1", Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", UpdatedAt: time.Now()},
		{ID: "doc-2", Hash: "ca35123a123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
		{ID: "doc-3", Hash: "8f435678123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
	}
	docsB := []sync.DocMetadata{
		{ID: "doc-3", Hash: "8f435678123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
		{ID: "doc-1", Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", UpdatedAt: time.Now()},
		{ID: "doc-2", Hash: "ca35123a123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
	}

	treeA := sync.BuildMerkleTree(docsA)
	treeB := sync.BuildMerkleTree(docsB)

	if !bytes.Equal(treeA.Hash, treeB.Hash) {
		t.Fatal("deterministic tree sorting failed: roots do not match for identical sets")
	}

	// Skewed set (doc-3 has different content, doc-4 is missing on B, doc-5 is missing on A)
	docsC := []sync.DocMetadata{
		{ID: "doc-1", Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", UpdatedAt: time.Now()},
		{ID: "doc-2", Hash: "ca35123a123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
		{ID: "doc-3", Hash: "different_hash_value_1234567890abcdef1234567890abcdef123456", UpdatedAt: time.Now()},
		{ID: "doc-4", Hash: "8f435678123f123a123a123a123a123a123a123a123a123a123a123a123a123a", UpdatedAt: time.Now()},
	}

	treeC := sync.BuildMerkleTree(docsC)
	diffs := sync.CompareMerkleTrees(treeA, treeC)

	// doc-3 has different hashes, and doc-4 is unique to C. Total diff count should include both
	diffMap := make(map[string]bool)
	for _, id := range diffs {
		diffMap[id] = true
	}

	if !diffMap["doc-3"] {
		t.Error("failed to isolate modified document ID doc-3")
	}
	if !diffMap["doc-4"] {
		t.Error("failed to isolate missing document ID doc-4")
	}
}

func TestSecureHandshake(t *testing.T) {
	password := "test_sync_password_123"

	// 1. Setup local network listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	errChan := make(chan error, 1)
	sessionChan := make(chan *crypto.Session, 1)

	// Server goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		defer conn.Close()

		sess, err := crypto.CompleteHandshake(conn, password)
		if err != nil {
			errChan <- err
			return
		}
		
		sessionChan <- sess
	}()

	// Client connection
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	clientSess, err := crypto.CompleteHandshake(conn, password)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}

	var serverSess *crypto.Session
	select {
	case serverSess = <-sessionChan:
	case err := <-errChan:
		t.Fatalf("server handshake failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("handshake timeout")
	}

	// 2. Verify encrypted channel flow
	plaintext := []byte("secret_p2p_synchronization_payload_data")
	
	// Client -> Server
	encMsg, err := clientSess.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("client encryption failed: %v", err)
	}

	decMsg, err := serverSess.Decrypt(encMsg)
	if err != nil {
		t.Fatalf("server decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decMsg) {
		t.Fatalf("decrypted data mismatch: got %q, expected %q", string(decMsg), string(plaintext))
	}
}
