package pqcratchet

// identity.go defines the Identity and RemoteIdentity types.
//
// Each peer has:
//   - A signing keypair (ML-DSA-65) — authenticates the exchange key and PreKeys
//   - An exchange keypair (Hybrid ML-KEM-768+X25519) — used in X3DH
//   - N signed PreKeys (hybrid KEM) — for X3DH initiator-responder setup
//   - N one-time PreKeys (hybrid KEM) — consumed on first use (optional)
//
// The exchange key is signed by the signing key at identity creation.
// Each signed PreKey is individually signed by the signing key.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Identity holds the long-term key material for a local peer.
type Identity struct {
	// mu protects PreKeys against concurrent OPK reservation in CreateSessionResponder.
	mu sync.Mutex

	ID            int
	SigningKey     *DSAKeyPair
	ExchangeKey   *HybridKEMKeyPair

	// ExchangeKeySignature is the signing key's signature over the exchange
	// public key bytes. Included in every PreKeyBundle so remote peers can
	// verify the binding.
	ExchangeKeySignature []byte

	// SignedPreKeys are medium-term KEM key pairs, each signed by SigningKey.
	SignedPreKeys      []*HybridKEMKeyPair
	SignedPreKeySigs   [][]byte // parallel slice: sig[i] covers SignedPreKeys[i].Public[:]

	// PreKeys are one-time KEM key pairs (unsigned, consumed on use).
	PreKeys []*HybridKEMKeyPair
}

// GenerateIdentity creates a fresh Identity with the given number of signed
// and one-time PreKeys.
func GenerateIdentity(id, signedPreKeyCount, preKeyCount int) (*Identity, error) {
	return generateIdentity(id, signedPreKeyCount, preKeyCount, rand.Reader)
}

func generateIdentity(id, signedPreKeyCount, preKeyCount int, r io.Reader) (*Identity, error) {
	sigKP, err := GenerateDSAKeyPair(r)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	exKP, err := GenerateKEMKeyPair(r)
	if err != nil {
		return nil, fmt.Errorf("generate exchange key: %w", err)
	}

	// Sign the exchange public key with the signing key.
	exSig, err := Sign(sigKP.Private, exKP.Public[:])
	if err != nil {
		return nil, fmt.Errorf("sign exchange key: %w", err)
	}

	ident := &Identity{
		ID:                   id,
		SigningKey:            sigKP,
		ExchangeKey:          exKP,
		ExchangeKeySignature: exSig,
	}

	// Generate signed PreKeys.
	ident.SignedPreKeys = make([]*HybridKEMKeyPair, signedPreKeyCount)
	ident.SignedPreKeySigs = make([][]byte, signedPreKeyCount)
	for i := range ident.SignedPreKeys {
		kp, err := GenerateKEMKeyPair(r)
		if err != nil {
			return nil, fmt.Errorf("generate signed pre-key %d: %w", i, err)
		}
		sig, err := Sign(sigKP.Private, kp.Public[:])
		if err != nil {
			return nil, fmt.Errorf("sign pre-key %d: %w", i, err)
		}
		ident.SignedPreKeys[i] = kp
		ident.SignedPreKeySigs[i] = sig
	}

	// Generate one-time PreKeys (unsigned).
	ident.PreKeys = make([]*HybridKEMKeyPair, preKeyCount)
	for i := range ident.PreKeys {
		kp, err := GenerateKEMKeyPair(r)
		if err != nil {
			return nil, fmt.Errorf("generate pre-key %d: %w", i, err)
		}
		ident.PreKeys[i] = kp
	}

	return ident, nil
}

// Thumbprint returns a hex-encoded SHA-256 digest of a public key byte slice.
// Used to compute the challenge PIN and as a stable identifier for remote peers.
func Thumbprint(pubKeyBytes []byte) string {
	h := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(h[:])
}

// ─── Remote Identity ─────────────────────────────────────────────────────────

// RemoteIdentity is a verified snapshot of a remote peer's public identity,
// assembled after signature verification (see VerifyPreKeyBundle /
// VerifyPreKeyMessage in session.go).
type RemoteIdentity struct {
	ID                  int
	SigningKeyBytes      []byte // DSAPublicKeySize bytes
	ExchangeKeyBytes    []byte // HybridPublicKeySize bytes
	ExchangeKeySig      []byte // DSASignatureSize bytes
	Thumbprint          string // hex SHA-256 of SigningKeyBytes
}

// ─── JSON serialisation ───────────────────────────────────────────────────────

type jsonIdentity struct {
	ID                   int      `json:"id"`
	SigningPriv          string   `json:"signingPriv"`  // hex
	SigningPub           string   `json:"signingPub"`   // hex
	ExchangePriv         string   `json:"exchangePriv"` // hex
	ExchangePub          string   `json:"exchangePub"`  // hex
	ExchangeKeySig       string   `json:"exchangeKeySig"` // hex
	SignedPreKeyPrivs    []string `json:"signedPreKeyPrivs"`
	SignedPreKeyPubs     []string `json:"signedPreKeyPubs"`
	SignedPreKeySigs     []string `json:"signedPreKeySigs"`
	PreKeyPrivs          []string `json:"preKeyPrivs"`
	PreKeyPubs           []string `json:"preKeyPubs"`
}

// MarshalJSON serialises the complete Identity including all private key material.
//
// Security warning: the output contains every private key held by this identity —
// the ML-DSA-65 signing private key, the KEM exchange private seed, all signed
// pre-key private seeds, and all one-time pre-key private seeds. This is the full
// long-term secret material for this identity. Callers are responsible for:
//
//   - Encrypting the output before writing it to disk or any persistent store.
//   - Never logging, transmitting, or including this data in error messages.
//   - Zeroing the JSON bytes after use (the Go GC does not guarantee zeroing of
//     freed memory).
//
// There is no encryption wrapper in this library — callers must provide their own
// key-wrapping layer (e.g. AES-GCM with a passphrase-derived key).
func (id *Identity) MarshalJSON() ([]byte, error) {
	sigPrivBytes, err := id.SigningKey.Private.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal signing private: %w", err)
	}
	sigPubBytes, err := id.SigningKey.Public.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal signing public: %w", err)
	}

	ji := jsonIdentity{
		ID:             id.ID,
		SigningPriv:    hex.EncodeToString(sigPrivBytes),
		SigningPub:     hex.EncodeToString(sigPubBytes),
		ExchangePriv:   hex.EncodeToString(id.ExchangeKey.Private[:]),
		ExchangePub:    hex.EncodeToString(id.ExchangeKey.Public[:]),
		ExchangeKeySig: hex.EncodeToString(id.ExchangeKeySignature),
	}

	for i, kp := range id.SignedPreKeys {
		ji.SignedPreKeyPrivs = append(ji.SignedPreKeyPrivs, hex.EncodeToString(kp.Private[:]))
		ji.SignedPreKeyPubs = append(ji.SignedPreKeyPubs, hex.EncodeToString(kp.Public[:]))
		ji.SignedPreKeySigs = append(ji.SignedPreKeySigs, hex.EncodeToString(id.SignedPreKeySigs[i]))
	}
	for _, kp := range id.PreKeys {
		if kp == nil {
			ji.PreKeyPrivs = append(ji.PreKeyPrivs, "")
			ji.PreKeyPubs = append(ji.PreKeyPubs, "")
			continue
		}
		ji.PreKeyPrivs = append(ji.PreKeyPrivs, hex.EncodeToString(kp.Private[:]))
		ji.PreKeyPubs = append(ji.PreKeyPubs, hex.EncodeToString(kp.Public[:]))
	}

	return json.Marshal(ji)
}

func (id *Identity) UnmarshalJSON(data []byte) error {
	var ji jsonIdentity
	if err := json.Unmarshal(data, &ji); err != nil {
		return err
	}

	sigPrivBytes, err := hex.DecodeString(ji.SigningPriv)
	if err != nil {
		return fmt.Errorf("decode signing private: %w", err)
	}
	sigPubBytes, err := hex.DecodeString(ji.SigningPub)
	if err != nil {
		return fmt.Errorf("decode signing public: %w", err)
	}
	sigPriv, err := ParseDSAPrivateKey(sigPrivBytes)
	if err != nil {
		return err
	}
	sigPub, err := ParseDSAPublicKey(sigPubBytes)
	if err != nil {
		return err
	}

	exPrivBytes, err := hex.DecodeString(ji.ExchangePriv)
	if err != nil {
		return fmt.Errorf("decode exchange private: %w", err)
	}
	exPubBytes, err := hex.DecodeString(ji.ExchangePub)
	if err != nil {
		return fmt.Errorf("decode exchange public: %w", err)
	}
	exSigBytes, err := hex.DecodeString(ji.ExchangeKeySig)
	if err != nil {
		return fmt.Errorf("decode exchange key sig: %w", err)
	}

	var exPriv HybridKEMPrivateKey
	var exPub HybridKEMPublicKey
	if len(exPrivBytes) != HybridPrivateKeySize {
		return fmt.Errorf("exchange private key wrong size: %d", len(exPrivBytes))
	}
	if len(exPubBytes) != HybridPublicKeySize {
		return fmt.Errorf("exchange public key wrong size: %d", len(exPubBytes))
	}
	copy(exPriv[:], exPrivBytes)
	copy(exPub[:], exPubBytes)

	id.ID = ji.ID
	id.SigningKey = &DSAKeyPair{Public: sigPub, Private: sigPriv}
	id.ExchangeKey = &HybridKEMKeyPair{Public: exPub, Private: exPriv}
	id.ExchangeKeySignature = exSigBytes

	id.SignedPreKeys = make([]*HybridKEMKeyPair, len(ji.SignedPreKeyPrivs))
	id.SignedPreKeySigs = make([][]byte, len(ji.SignedPreKeyPrivs))
	if len(ji.SignedPreKeyPubs) != len(ji.SignedPreKeyPrivs) {
		return fmt.Errorf("identity: SignedPreKeyPubs length %d != SignedPreKeyPrivs length %d",
			len(ji.SignedPreKeyPubs), len(ji.SignedPreKeyPrivs))
	}
	if len(ji.SignedPreKeySigs) != len(ji.SignedPreKeyPrivs) {
		return fmt.Errorf("identity: SignedPreKeySigs length %d != SignedPreKeyPrivs length %d",
			len(ji.SignedPreKeySigs), len(ji.SignedPreKeyPrivs))
	}
	for i := range ji.SignedPreKeyPrivs {
		privBytes, err := hex.DecodeString(ji.SignedPreKeyPrivs[i])
		if err != nil {
			return fmt.Errorf("identity: signed pre-key %d private: %w", i, err)
		}
		pubBytes, err := hex.DecodeString(ji.SignedPreKeyPubs[i])
		if err != nil {
			return fmt.Errorf("identity: signed pre-key %d public: %w", i, err)
		}
		sigBytes, err := hex.DecodeString(ji.SignedPreKeySigs[i])
		if err != nil {
			return fmt.Errorf("identity: signed pre-key %d sig: %w", i, err)
		}
		if len(privBytes) != HybridPrivateKeySize {
			return fmt.Errorf("identity: signed pre-key %d private wrong size: %d", i, len(privBytes))
		}
		if len(pubBytes) != HybridPublicKeySize {
			return fmt.Errorf("identity: signed pre-key %d public wrong size: %d", i, len(pubBytes))
		}
		var priv HybridKEMPrivateKey
		var pub HybridKEMPublicKey
		copy(priv[:], privBytes)
		copy(pub[:], pubBytes)
		id.SignedPreKeys[i] = &HybridKEMKeyPair{Public: pub, Private: priv}
		id.SignedPreKeySigs[i] = sigBytes
	}

	id.PreKeys = make([]*HybridKEMKeyPair, len(ji.PreKeyPrivs))
	if len(ji.PreKeyPubs) != len(ji.PreKeyPrivs) {
		return fmt.Errorf("identity: PreKeyPubs length %d != PreKeyPrivs length %d",
			len(ji.PreKeyPubs), len(ji.PreKeyPrivs))
	}
	for i := range ji.PreKeyPrivs {
		if ji.PreKeyPrivs[i] == "" {
			continue // consumed one-time key
		}
		privBytes, err := hex.DecodeString(ji.PreKeyPrivs[i])
		if err != nil {
			return fmt.Errorf("identity: pre-key %d private: %w", i, err)
		}
		pubBytes, err := hex.DecodeString(ji.PreKeyPubs[i])
		if err != nil {
			return fmt.Errorf("identity: pre-key %d public: %w", i, err)
		}
		if len(privBytes) != HybridPrivateKeySize {
			return fmt.Errorf("identity: pre-key %d private wrong size: %d", i, len(privBytes))
		}
		if len(pubBytes) != HybridPublicKeySize {
			return fmt.Errorf("identity: pre-key %d public wrong size: %d", i, len(pubBytes))
		}
		var priv HybridKEMPrivateKey
		var pub HybridKEMPublicKey
		copy(priv[:], privBytes)
		copy(pub[:], pubBytes)
		id.PreKeys[i] = &HybridKEMKeyPair{Public: pub, Private: priv}
	}

	return nil
}
