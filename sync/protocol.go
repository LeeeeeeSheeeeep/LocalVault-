package sync

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"
)

// DocMetadata represents the identity and hash of a single document
type DocMetadata struct {
	ID        string
	Hash      string // Hex string of the SHA-256 document content
	UpdatedAt time.Time
}

// MerkleNode represents a node in the cryptographic binary Merkle Tree
type MerkleNode struct {
	Hash  []byte
	Left  *MerkleNode
	Right *MerkleNode
	DocID string // Only set on leaf nodes
}

// BuildMerkleTree constructs a Merkle Tree from list of document metadata
func BuildMerkleTree(docs []DocMetadata) *MerkleNode {
	if len(docs) == 0 {
		h := sha256.Sum256([]byte("EMPTY_VAULT"))
		return &MerkleNode{Hash: h[:]}
	}

	// 1. Sort documents by ID to guarantee deterministic tree structure on both peers
	sortedDocs := make([]DocMetadata, len(docs))
	copy(sortedDocs, docs)
	sort.Slice(sortedDocs, func(i, j int) bool {
		return sortedDocs[i].ID < sortedDocs[j].ID
	})

	// 2. Build leaf level
	var nodes []*MerkleNode
	for _, doc := range sortedDocs {
		docHashBytes, _ := hex.DecodeString(doc.Hash)
		
		// Leaf Hash = SHA-256(DocID + DocContentHash)
		hasher := sha256.New()
		hasher.Write([]byte(doc.ID))
		hasher.Write(docHashBytes)
		leafHash := hasher.Sum(nil)

		nodes = append(nodes, &MerkleNode{
			Hash:  leafHash,
			DocID: doc.ID,
		})
	}

	// 3. Build tree bottom-up
	for len(nodes) > 1 {
		var nextLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				// Pair node hashes: SHA-256(LeftHash + RightHash)
				hasher := sha256.New()
				hasher.Write(nodes[i].Hash)
				hasher.Write(nodes[i+1].Hash)
				parentHash := hasher.Sum(nil)

				nextLevel = append(nextLevel, &MerkleNode{
					Hash:  parentHash,
					Left:  nodes[i],
					Right: nodes[i+1],
				})
			} else {
				// Odd node: duplicate the hash
				hasher := sha256.New()
				hasher.Write(nodes[i].Hash)
				hasher.Write(nodes[i].Hash)
				parentHash := hasher.Sum(nil)

				nextLevel = append(nextLevel, &MerkleNode{
					Hash: parentHash,
					Left: nodes[i],
				})
			}
		}
		nodes = nextLevel
	}

	return nodes[0]
}

// CompareMerkleTrees traverses and compares two Merkle nodes to isolate modified/missing DocIDs.
// Returns localDocIDs, remoteDocIDs that are out of sync.
func CompareMerkleTrees(localRoot, remoteRoot *MerkleNode) []string {
	var diffs []string
	compareNodes(localRoot, remoteRoot, &diffs)
	return diffs
}

func compareNodes(local, remote *MerkleNode, diffs *[]string) {
	if local == nil && remote == nil {
		return
	}
	if local == nil {
		collectAllLeafIDs(remote, diffs)
		return
	}
	if remote == nil {
		collectAllLeafIDs(local, diffs)
		return
	}

	// Hashes match: subtree is perfectly in sync
	if hex.EncodeToString(local.Hash) == hex.EncodeToString(remote.Hash) {
		return
	}

	// Leaf level reached
	if local.DocID != "" && remote.DocID != "" {
		if local.DocID == remote.DocID {
			*diffs = append(*diffs, local.DocID)
		} else {
			*diffs = append(*diffs, local.DocID)
			*diffs = append(*diffs, remote.DocID)
		}
		return
	}

	// Local leaf, Remote branch: remote is larger or skewed
	if local.DocID != "" {
		*diffs = append(*diffs, local.DocID)
		collectAllLeafIDs(remote, diffs)
		return
	}

	// Local branch, Remote leaf
	if remote.DocID != "" {
		*diffs = append(*diffs, remote.DocID)
		collectAllLeafIDs(local, diffs)
		return
	}

	// Both are branches: recursively check children
	compareNodes(local.Left, remote.Left, diffs)
	compareNodes(local.Right, remote.Right, diffs)
}

func collectAllLeafIDs(n *MerkleNode, list *[]string) {
	if n == nil {
		return
	}
	if n.DocID != "" {
		*list = append(*list, n.DocID)
		return
	}
	collectAllLeafIDs(n.Left, list)
	collectAllLeafIDs(n.Right, list)
}

// Frame Transport Helpers: Prefix packets with 4-byte length header for stream framing
func WriteFrame(w io.Writer, payload []byte) error {
	length := uint32(len(payload))
	err := binary.Write(w, binary.BigEndian, length)
	if err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var length uint32
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}

	// Protect against buffer overflows (limit packet frame sizes to 50MB)
	if length > 50*1024*1024 {
		return nil, fmt.Errorf("read frame exceeds limit size: %d bytes", length)
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
