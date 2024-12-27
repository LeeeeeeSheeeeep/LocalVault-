package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// Session represents an active secure encrypted connection envelope
type Session struct {
	aesGCM cipher.AEAD
}

// GenerateEphemeralKey creates a new P-256 ECDH private/public key pair
func GenerateEphemeralKey() (*ecdsa.PrivateKey, []byte, error) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubBytes := elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y)
	return priv, pubBytes, nil
}

// DeriveSharedSecret computes the ECDH shared secret and derives an AES key with password auth
func DeriveSharedSecret(priv *ecdsa.PrivateKey, peerPubBytes []byte, syncPassword string) ([]byte, error) {
	curve := elliptic.P256()
	peerX, peerY := elliptic.Unmarshal(curve, peerPubBytes)
	if peerX == nil || peerY == nil {
		return nil, errors.New("invalid peer public key")
	}

	// Verify public key is on the curve
	if !curve.IsOnCurve(peerX, peerY) {
		return nil, errors.New("peer public key is not on elliptic curve P-256")
	}

	// Compute shared secret: S = priv.D * peerPub
	x, _ := curve.ScalarMult(peerX, peerY, priv.D.Bytes())
	sharedSecret := x.Bytes()

	// Compute Key Derivation Function (KDF): HMAC-SHA256(sharedSecret, password)
	mac := hmac.New(sha256.New, []byte(syncPassword))
	mac.Write(sharedSecret)
	derivedKey := mac.Sum(nil)

	return derivedKey, nil
}

// CompleteHandshake performs mutual authentication over a net.Conn stream
func CompleteHandshake(rw io.ReadWriter, syncPassword string) (*Session, error) {
	// 1. Generate ephemeral ECDH key
	priv, pubBytes, err := GenerateEphemeralKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate handshake key: %w", err)
	}

	// 2. Write our public key to stream (exactly 65 bytes for elliptic.P256 uncompressed)
	if len(pubBytes) != 65 {
		return nil, fmt.Errorf("invalid local public key size: %d", len(pubBytes))
	}
	_, err = rw.Write(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write public key to peer: %w", err)
	}

	// 3. Read peer's public key from stream
	peerPubBytes := make([]byte, 65)
	_, err = io.ReadFull(rw, peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read peer public key: %w", err)
	}

	// 4. Derive symmetric key
	key, err := DeriveSharedSecret(priv, peerPubBytes, syncPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// 5. Generate and exchange verification HMACs to prove password knowledge
	localVerifier := computeVerifier(key, pubBytes, peerPubBytes)
	_, err = rw.Write(localVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to write local verifier: %w", err)
	}

	peerVerifier := make([]byte, 32)
	_, err = io.ReadFull(rw, peerVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to read peer verifier: %w", err)
	}

	expectedPeerVerifier := computeVerifier(key, peerPubBytes, pubBytes)
	if subtle.ConstantTimeCompare(peerVerifier, expectedPeerVerifier) != 1 {
		return nil, errors.New("mutual authentication failed: invalid sync credentials")
	}

	// 6. Setup AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Session{aesGCM: aesGCM}, nil
}

func computeVerifier(key, senderPub, receiverPub []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(senderPub)
	mac.Write(receiverPub)
	mac.Write([]byte("LOCALVAULT_AUTH_VERIFIER"))
	return mac.Sum(nil)
}

// Encrypt wraps plaintext into an AES-GCM envelope (nonce + ciphertext)
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := s.aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt unwraps an AES-GCM envelope
func (s *Session) Decrypt(packet []byte) ([]byte, error) {
	nonceSize := s.aesGCM.NonceSize()
	if len(packet) < nonceSize {
		return nil, errors.New("packet too short: missing cipher nonce")
	}
	nonce := packet[:nonceSize]
	ciphertext := packet[nonceSize:]
	return s.aesGCM.Open(nil, nonce, ciphertext, nil)
}
