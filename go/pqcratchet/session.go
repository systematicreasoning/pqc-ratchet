package pqcratchet

// session.go manages Double Ratchet sessions with a KEM ratchet.
//
// The key structural difference from the classical implementation is the
// KEM ratchet step:
//
//   Classical: sender computes DH(ourPriv, theirPub) → shared secret
//   KEM:       sender encapsulates against theirPub → (ct, ss)
//              ct is sent in the message header
//              receiver decapsulates with theirPriv → ss
//
// This means:
//   - EncryptMessage must generate a new KEM keypair, encapsulate against the
//     remote ratchet key, and include the ciphertext in the message.
//   - DecryptMessage receives that ciphertext and decapsulates using the local
//     ratchet private key.
//   - The session must track both the current local KEM keypair (for the
//     sending ratchet) and the remote ratchet KEM public key.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// DefaultSkippedKeyTTL is how long skipped message keys are retained.
const DefaultSkippedKeyTTL = 1 * time.Hour

type skippedKeyEntry struct {
	Keys     *MessageKeys
	CachedAt time.Time
}

// Session manages the Double Ratchet state for a single peer connection.
type Session struct {
	mu sync.Mutex

	Identity       *Identity
	RemoteIdentity *RemoteIdentity

	RootKey     []byte // 32-byte ratchet root key
	CurrentStep *KEMRatchetStep
	Steps       []*KEMRatchetStep

	// Our current KEM ratchet keypair.
	// On the sending ratchet, we encapsulate against RemoteRatchetKey.
	// The private key stays local; only the ciphertext is transmitted.
	RatchetKP *HybridKEMKeyPair

	// AD is the Associated Data for this session, per X3DH spec §3.3:
	//   AD = Encode(IKA) || Encode(IKB)
	// where IKA and IKB are the initiator's and responder's identity
	// exchange public keys respectively.
	// AD is included in every message HMAC to bind message authentication
	// to the specific session identity keys. This prevents a message
	// authenticated in one session from being replayed into another.
	AD []byte

	// Signing key bytes for HMAC authentication.
	// These use stable session roles (initiator/responder) rather than the
	// dynamic local/remote perspective, so both sides compute the same HMAC
	// input regardless of who is encrypting.
	//
	// InitiatorSigningKeyBytes: Alice's ML-DSA-65 public key bytes (never changes).
	// ResponderSigningKeyBytes: Bob's ML-DSA-65 public key bytes (never changes).
	InitiatorSigningKeyBytes []byte
	ResponderSigningKeyBytes []byte

	// SkippedKeys caches message keys for out-of-order delivery.
	// Key: "ratchetKeyHex:counter"
	SkippedKeys   map[string]*skippedKeyEntry
	SkippedKeyTTL time.Duration
}

// ─── Bundle / message verification ───────────────────────────────────────────

// PreKeyBundle is a verified, parsed PreKeyBundle ready for session creation.
type PreKeyBundle struct {
	RegistrationID         int
	IdentitySigningPub     *DSAPublicKey
	IdentitySigningPubBytes []byte
	IdentityExchangePub    *HybridKEMPublicKey
	SignedPreKeyPub        *HybridKEMPublicKey
	SignedPreKeyIndex      int
	OneTimePreKeyPub       *HybridKEMPublicKey // may be nil
	OneTimePreKeyIndex     int                 // -1 if none
}

// PreKeyMessage is a verified, parsed PreKeyMessage ready for session creation.
type PreKeyMessage struct {
	RegistrationID          int
	SignedPreKeyIndex        int
	OneTimePreKeyIndex      int // -1 if none
	IdentitySigningPub      *DSAPublicKey
	IdentitySigningPubBytes []byte
	IdentityExchangePub     *HybridKEMPublicKey
	// BaseKey is Alice's ephemeral KEM public key (EK_A).
	// This becomes the initial remote ratchet key for Bob.
	BaseKey *HybridKEMPublicKey
	// KEM ciphertexts from Alice's X3DH computation.
	CT1, CT2 *HybridKEMCiphertext
	CT4      *HybridKEMCiphertext // nil if no OPK
	// InitiatorSig is Alice's ML-DSA-65 signature over the X3DH transcript.
	// Verified by AuthenticateB before any decapsulation.
	InitiatorSig []byte
	// The first encrypted message, if bundled.
	SignedMessage *ParsedMessageSigned
}

// ─── Session creation ─────────────────────────────────────────────────────────

// CreateSessionInitiator builds a session from a verified PreKeyBundle.
// This is Alice's side.
func CreateSessionInitiator(identity *Identity, bundle *PreKeyBundle) (*Session, *KEMInitiatorResult, error) {
	return createSessionInitiator(identity, bundle, rand.Reader)
}

// buildAD constructs the X3DH Associated Data per spec §3.3:
//
//	AD = Encode(IKA) || Encode(IKB)
//
// IKA is the initiator's identity exchange public key; IKB is the responder's.
// These are the KEM exchange keys, not the signing keys. AD is stable for the
// lifetime of the session and is used as GCM additional data and mixed into
// every outer HMAC.
//
// Ordering constraint: the initiator (Alice) key MUST be passed first. Both
// parameters have the same type, so a transposition compiles silently but
// produces a different AD than the peer, causing every GCM Open and every
// outer HMAC verification to fail. If adding a new session creation path,
// verify against the existing call sites that Alice's key is argument 1.
func buildAD(initiatorExchangePub, responderExchangePub *HybridKEMPublicKey) []byte {
	ad := make([]byte, HybridPublicKeySize*2)
	copy(ad[:HybridPublicKeySize], initiatorExchangePub[:])
	copy(ad[HybridPublicKeySize:], responderExchangePub[:])
	return ad
}

func createSessionInitiator(identity *Identity, bundle *PreKeyBundle, r io.Reader) (*Session, *KEMInitiatorResult, error) {
	result, err := authenticateA(
		r,
		identity.SigningKey.Private,
		&identity.ExchangeKey.Public,
		bundle.IdentityExchangePub,
		bundle.SignedPreKeyPub,
		bundle.OneTimePreKeyPub,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh initiator: %w", err)
	}

	// Alice is the initiator, Bob is the responder.
	initiatorSigningPubBytes := DSAPublicKeyBytes(identity.SigningKey.Public)
	responderSigningPubBytes := DSAPublicKeyBytes(bundle.IdentitySigningPub)

	// AD = Encode(IKA) || Encode(IKB): initiator exchange key first, per spec §3.3.
	ad := buildAD(&identity.ExchangeKey.Public, bundle.IdentityExchangePub)

	sess := &Session{
		Identity: identity,
		RemoteIdentity: &RemoteIdentity{
			ID:               bundle.RegistrationID,
			SigningKeyBytes:   responderSigningPubBytes,
			ExchangeKeyBytes: bundle.IdentityExchangePub[:],
			Thumbprint:       Thumbprint(responderSigningPubBytes),
		},
		RootKey: result.RootKey,
		// Alice's ephemeral keypair is also the initial ratchet keypair.
		// Per X3DH spec §3.3, the ephemeral private key must be deleted after
		// SK is computed. Here it is retained only as RatchetKP for the first
		// ratchet step. The caller MUST call ZeroKEMKeyPair(result.EphemeralKP)
		// after CreateSessionInitiator returns to clear the copy in the result.
		// The ratchet will overwrite RatchetKP on the first sending step.
		RatchetKP: result.EphemeralKP,
		CurrentStep: &KEMRatchetStep{
			// Bob's signed pre-key is Alice's initial remote ratchet key.
			RemoteRatchetKey: bundle.SignedPreKeyPub,
		},
		AD:                       ad,
		InitiatorSigningKeyBytes: initiatorSigningPubBytes,
		ResponderSigningKeyBytes: responderSigningPubBytes,
		SkippedKeys:              make(map[string]*skippedKeyEntry),
		SkippedKeyTTL:            DefaultSkippedKeyTTL,
	}

	return sess, result, nil
}

// CreateSessionResponder builds a session from a verified PreKeyMessage.
// This is Bob's side. Returns ErrInvalidSignature if Alice's X3DH transcript
// signature does not verify — the session must not be used in that case.
//
// Replay warning: If no one-time pre-key was used, Alice's PreKeyMessage can be
// replayed to Bob and he will accept it, deriving the same root key each time.
// Per X3DH spec §4.2, the post-X3DH protocol (this Double Ratchet) mitigates
// this by requiring Bob to contribute fresh randomness before sending, which
// randomises the encryption key. Applications SHOULD use one-time pre-keys
// whenever possible to eliminate the replay window entirely.
func CreateSessionResponder(identity *Identity, msg *PreKeyMessage) (*Session, error) {
	if msg.SignedPreKeyIndex >= len(identity.SignedPreKeys) {
		return nil, fmt.Errorf("signed pre-key %d not found", msg.SignedPreKeyIndex)
	}

	// Reserve the one-time pre-key under identity.mu to prevent concurrent
	// CreateSessionResponder calls from observing the same OPK as non-nil
	// and reusing it (TOCTOU / double-use). The slot is set to nil while
	// holding the lock; on AuthenticateB failure it is restored (also under
	// the lock) so unauthenticated or malformed requests do not permanently
	// consume a key.
	var oneTimePreKeyPriv *HybridKEMPrivateKey
	var oneTimePreKeyKP *HybridKEMKeyPair // held for zeroing after use
	var oneTimePreKeyIndex int = -1
	identity.mu.Lock()
	if msg.OneTimePreKeyIndex >= 0 && msg.OneTimePreKeyIndex < len(identity.PreKeys) {
		kp := identity.PreKeys[msg.OneTimePreKeyIndex]
		if kp != nil {
			oneTimePreKeyPriv = &kp.Private
			oneTimePreKeyKP = kp
			oneTimePreKeyIndex = msg.OneTimePreKeyIndex
			identity.PreKeys[msg.OneTimePreKeyIndex] = nil
		}
	}
	identity.mu.Unlock()

	signedPreKP := identity.SignedPreKeys[msg.SignedPreKeyIndex]

	rootKey, err := AuthenticateB(
		&identity.ExchangeKey.Private,
		&signedPreKP.Private,
		oneTimePreKeyPriv,
		msg.IdentitySigningPub,
		msg.IdentityExchangePub,
		msg.BaseKey,
		msg.CT1, msg.CT2,
		msg.CT4,
		msg.InitiatorSig,
	)
	if err != nil {
		// Authentication failed — restore the OPK slot so the key is not
		// permanently consumed by an unauthenticated or malformed request.
		// The private key bytes have not been zeroed yet so restoration is safe.
		if oneTimePreKeyIndex >= 0 {
			identity.mu.Lock()
			// Only restore if the slot is still nil; a concurrent legitimate
			// session may have already consumed another OPK at this index
			// (shouldn't happen given monotonic index assignment, but be safe).
			if identity.PreKeys[oneTimePreKeyIndex] == nil {
				identity.PreKeys[oneTimePreKeyIndex] = oneTimePreKeyKP
			}
			identity.mu.Unlock()
		}
		return nil, fmt.Errorf("x3dh responder: %w", err)
	}
	// Zero the OPK private key NOW — after AuthenticateB has finished using it
	// and only on success. Per X3DH spec §3.4: "Bob deletes any one-time prekey
	// private key that was used."
	if oneTimePreKeyKP != nil {
		ZeroKEMKeyPair(oneTimePreKeyKP)
	}

	// Alice is the initiator (msg sender), Bob is the responder (identity).
	initiatorSigningPubBytes := DSAPublicKeyBytes(msg.IdentitySigningPub)
	responderSigningPubBytes := DSAPublicKeyBytes(identity.SigningKey.Public)

	// AD = Encode(IKA) || Encode(IKB): initiator (Alice) exchange key first.
	// msg.IdentityExchangePub is Alice's IKA; identity.ExchangeKey.Public is Bob's IKB.
	var responderExchangePub HybridKEMPublicKey
	copy(responderExchangePub[:], identity.ExchangeKey.Public[:])
	ad := buildAD(msg.IdentityExchangePub, &responderExchangePub)

	sess := &Session{
		Identity: identity,
		RemoteIdentity: &RemoteIdentity{
			ID:               msg.RegistrationID,
			SigningKeyBytes:   initiatorSigningPubBytes,
			ExchangeKeyBytes: msg.IdentityExchangePub[:],
			Thumbprint:       Thumbprint(initiatorSigningPubBytes),
		},
		RootKey: rootKey,
		// Bob's initial ratchet KP is the signed pre-key he already holds.
		RatchetKP: signedPreKP,
		CurrentStep: &KEMRatchetStep{
			// Alice's ephemeral KEM public key (BaseKey) is Bob's initial remote ratchet key.
			RemoteRatchetKey: msg.BaseKey,
		},
		AD:                       ad,
		InitiatorSigningKeyBytes: initiatorSigningPubBytes,
		ResponderSigningKeyBytes: responderSigningPubBytes,
		SkippedKeys:              make(map[string]*skippedKeyEntry),
		SkippedKeyTTL:            DefaultSkippedKeyTTL,
	}

	return sess, nil
}

// ─── KEM ratchet ─────────────────────────────────────────────────────────────

// CreateChainFromKEM derives a new symmetric chain from a KEM shared secret.
//
// These two functions implement the KEM-based Continuous Key Agreement (CKA)
// scheme of Alwen, Coretti, Dodis (ACD19) [1], Section 3.3:
//
//   createSendingChain  → ACD19 CKA-S (sender step)
//   createReceivingChain → ACD19 CKA-R (receiver step)
//
// In ACD19 terms, CKA-S generates a fresh public key (RatchetKP.Public) and
// encapsulates against the remote ratchet key (EpochRatchetCT). CKA-R
// decapsulates the ciphertext using the local ratchet private key. Both
// functions feed the resulting KEM shared secret into advanceRootKey (KDF_RK
// in the Double Ratchet spec [2] §2.2) to produce a new root key and chain key.
//
// Security: ACD19 Theorem 2 proves CKA security under IND-CCA2 of the KEM.
// ML-KEM-768 is IND-CCA2 secure under MLWE (FIPS 203).
//
//   [1] https://eprint.iacr.org/2018/1037
//   [2] https://signal.org/docs/specifications/doubleratchet/
//
// The encapsulator side:
//
//	(ct, ss) = KEM.Encap(remoteRatchetPub)
//	newRootKey, chainKey = HKDF(ss, oldRootKey, "InfoRatchet")
//
// The decapsulator side:
//
//	ss = KEM.Decap(localRatchetPriv, ct)
//	newRootKey, chainKey = HKDF(ss, oldRootKey, "InfoRatchet")
//
// Both sides derive the same newRootKey and chainKey from the same ss.
func (s *Session) createSendingChain(r io.Reader, remoteRatchetPub *HybridKEMPublicKey) (*SymmetricChain, *HybridKEMCiphertext, error) {
	ct, ss, err := Encapsulate(r, remoteRatchetPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet encap: %w", err)
	}
	chain, err := s.advanceRootKey(ss)
	if err != nil {
		return nil, nil, err
	}
	return chain, ct, nil
}

func (s *Session) createReceivingChain(localRatchetPriv *HybridKEMPrivateKey, ct *HybridKEMCiphertext) (*SymmetricChain, error) {
	ss, err := Decapsulate(localRatchetPriv, ct)
	if err != nil {
		return nil, fmt.Errorf("ratchet decap: %w", err)
	}
	// After decapsulation, s.RatchetKP.Private is still held in session state.
	// It is NOT zeroed here — it is needed as the decapsulation key for the
	// current epoch and is only replaced (and the old key zeroed) when
	// encryptMessage() generates a new keypair for the next sending epoch.
	//
	// This means ∆_CKA = 1: if an adversary compromises state between receiving
	// epoch t and sending the first message of epoch t+1, they can reconstruct
	// the receiving chain key for epoch t. Post-compromise security (PCS) is
	// therefore restored in ∆_SM = 3 rounds rather than the theoretical minimum
	// of 2 (which would require zeroing RatchetKP.Private here, at the cost of
	// a more complex sending-epoch bootstrapping path). This matches Signal's
	// deployed DH ratchet behaviour. See ACD19 §3.3 and DESIGN.md §Formal security.
	return s.advanceRootKey(ss)
}

// advanceRootKey implements KDF_RK from the Double Ratchet spec [1] §2.2,
// and corresponds to the PRF-PRNG component of the ACD19 modular framework [2].
//
// ACD19 requires a two-input function F(k, r) that is a PRF in the first
// input (k = ss, the KEM shared secret) and a PRG in the second input
// (r = RootKey, the chained state). HKDF-SHA-256 satisfies this in the
// random oracle model.
//
//	KDF_RK(rootKey, ss) → (newRootKey, chainKey)
//
// Per the DR spec §2.2, rootKey is the HKDF key (PRK) and ss (the KEM shared
// secret) is the input key material. Using HKDF-Extract(salt=rootKey, IKM=ss)
// gives a tighter security reduction than using rootKey as the HKDF salt:
// the output is pseudorandom under the assumption that rootKey is pseudorandom,
// regardless of the distribution of ss. This matches the spec's intent that
// KDF_RK "uses RK as the HKDF key".
//
//	[1] https://signal.org/docs/specifications/doubleratchet/
//	[2] https://eprint.iacr.org/2018/1037
func (s *Session) advanceRootKey(ss []byte) (*SymmetricChain, error) {
	// HKDF-Extract: PRK = HMAC-SHA256(salt=RootKey, IKM=ss)
	//
	// RFC 5869 §2.2 defines: PRK = HMAC-Hash(salt, IKM)
	// Go's hkdf.Extract signature is: Extract(hash, secret, salt) — note the
	// argument order differs from the RFC. Mapping: secret=ss (IKM), salt=RootKey.
	// https://www.rfc-editor.org/rfc/rfc5869#section-2.2
	//
	// RootKey acts as the HKDF salt. Per the DR spec §2.2, KDF_RK is keyed
	// by the root key, which maps to the salt position in RFC 5869 Extract.
	prk := hkdf.Extract(sha256.New, ss, s.RootKey)

	// HKDF-Expand: derive 64 bytes — first 32 are the new root key,
	// next 32 are the new chain key.
	expander := hkdf.Expand(sha256.New, prk, infoRatchet)

	newRootKey := make([]byte, 32)
	chainKey := make([]byte, 32)
	if _, err := io.ReadFull(expander, newRootKey); err != nil {
		return nil, fmt.Errorf("ratchet HKDF root: %w", err)
	}
	if _, err := io.ReadFull(expander, chainKey); err != nil {
		return nil, fmt.Errorf("ratchet HKDF chain: %w", err)
	}

	s.RootKey = newRootKey
	return &SymmetricChain{RootKey: chainKey}, nil
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

// EncryptResult bundles everything the caller needs to build a wire message.
type EncryptResult struct {
	Ciphertext []byte
	// HMACKey is the outer session HMAC key for MarshalSignedMessage.
	// This is separate from AES-GCM's internal authentication tag — see
	// MessageKeys for the two-layer authentication explanation.
	HMACKey []byte
	Counter int
	// RatchetCT is the KEM ciphertext for this sending epoch. Non-nil on every
	// message so any message can bootstrap the receiver's chain for out-of-order
	// delivery.
	RatchetCT *HybridKEMCiphertext
	// NewRatchetPub is a pointer into the session's live RatchetKP.Public.
	// Valid only until the next ratchet step — serialise before the next
	// EncryptMessage call.
	NewRatchetPub *HybridKEMPublicKey
}

// ─── High-level API ───────────────────────────────────────────────────────────
//
// Seal and Open are the recommended API for most callers.
// They handle wire marshalling, HMAC construction, and signing internally so
// the caller only deals with plaintext bytes and opaque wire frames.
//
// The lower-level EncryptMessage / DecryptSignedMessage + Marshal* functions
// remain available for advanced use: custom transports, server-side batching,
// audit tooling.

// Seal encrypts plaintext and returns a self-contained, authenticated wire
// frame ready to transmit.  Pass the returned bytes to the recipient's Open.
//
// The frame includes: message counter, sender ratchet public key, optional KEM
// ciphertext (on the first message of a new ratchet turn), the AES-256-GCM
// ciphertext, and an outer HMAC-SHA-256 authentication tag.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	enc, err := s.EncryptMessage(plaintext)
	if err != nil {
		return nil, err
	}
	inner := MarshalMessageProtocol(&ParsedMessageProtocol{
		Counter:         uint32(enc.Counter),
		SenderRatchetPub: enc.NewRatchetPub,
		RatchetCT:       enc.RatchetCT,
		CipherText:      enc.Ciphertext,
	})
	return MarshalSignedMessage(inner, enc.HMACKey, s.AD, s.InitiatorSigningKeyBytes, s.ResponderSigningKeyBytes), nil
}

// Open verifies and decrypts a wire frame produced by the remote side's Seal.
// Returns the plaintext or an error if authentication fails, the ratchet state
// is inconsistent, or the message is a duplicate.
func (s *Session) Open(wireBytes []byte) ([]byte, error) {
	msg, err := UnmarshalSignedMessage(wireBytes)
	if err != nil {
		return nil, err
	}
	return s.DecryptSignedMessage(msg)
}

// EncryptMessage encrypts plaintext, advancing the ratchet if necessary.
func (s *Session) EncryptMessage(plaintext []byte) (*EncryptResult, error) {
	return s.encryptMessage(plaintext, rand.Reader)
}

func (s *Session) encryptMessage(plaintext []byte, r io.Reader) (*EncryptResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := &EncryptResult{}

	// If we have a receiving chain but no sending chain, take a KEM ratchet step:
	// generate a new KEM keypair and encapsulate against the remote ratchet key.
	// Zero the old ratchet private key before replacing it — per X3DH spec §3.3,
	// ephemeral private keys must be deleted after use to provide forward secrecy.
	if s.CurrentStep.ReceivingChain != nil && s.CurrentStep.SendingChain == nil {
		oldKP := s.RatchetKP
		newKP, err := GenerateKEMKeyPair(r)
		if err != nil {
			return nil, fmt.Errorf("ratchet keygen: %w", err)
		}
		ZeroKEMKeyPair(oldKP)
		s.RatchetKP = newKP
	}

	// Ensure we have a sending chain.
	if s.CurrentStep.SendingChain == nil {
		if s.CurrentStep.RemoteRatchetKey == nil {
			return nil, ErrNoRatchetKey
		}
		chain, ct, err := s.createSendingChain(r, s.CurrentStep.RemoteRatchetKey)
		if err != nil {
			return nil, err
		}
		s.CurrentStep.SendingChain = chain
		s.CurrentStep.EpochRatchetCT = ct
	}

	// Step the symmetric chain.
	cipherKey, err := s.CurrentStep.SendingChain.Step()
	if err != nil {
		return nil, err
	}

	mk, err := DeriveMessageKeys(cipherKey)
	if err != nil {
		return nil, err
	}

	ct, err := AESGCMEncrypt(mk.AESKey, mk.Nonce, s.AD, plaintext)
	if err != nil {
		return nil, err
	}

	res.Ciphertext = ct
	res.HMACKey = mk.HMACKey
	res.Counter = s.CurrentStep.SendingChain.Counter - 1
	// Always carry the epoch's RatchetCT so any message can bootstrap the
	// receiver's chain regardless of arrival order.
	res.RatchetCT = s.CurrentStep.EpochRatchetCT
	// Always carry the current ratchet public key so the receiver can
	// identify which epoch this message belongs to.
	res.NewRatchetPub = &s.RatchetKP.Public

	return res, nil
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

// IncomingMessage contains everything needed to decrypt a received message.
type IncomingMessage struct {
	Ciphertext []byte
	// RatchetPub is the sender's current ratchet KEM public key.
	RatchetPub *HybridKEMPublicKey
	// RatchetCT is the KEM ciphertext for this ratchet step (nil if sender
	// reused the existing chain without a ratchet step).
	RatchetCT *HybridKEMCiphertext
	Counter   int
}

// ratchetSnapshot captures all session state that deriveMessageKeys might
// mutate so we can roll back if HMAC verification fails.
//
// RatchetKP is included even though deriveMessageKeysLocked does not modify
// it directly. This closes a structural gap: createReceivingChain reads
// s.RatchetKP.Private, and if encryptMessage ever zeroes RatchetKP between
// snapshot and HMAC verification (impossible under the current mutex design,
// but fragile if threading changes), a rollback must also restore RatchetKP.
// Snapshotting it here makes the invariant explicit and enforced rather than
// relying on an implicit ordering assumption.
//
// Note: we snapshot the pointer, not a deep copy of the key material. This is
// safe because encryptMessage replaces s.RatchetKP with a new allocation
// (ZeroKEMKeyPair(oldKP); s.RatchetKP = newKP) rather than mutating the
// existing struct in place. Restoring the pointer restores the old keypair.
type ratchetSnapshot struct {
	rootKey     []byte
	currentStep *KEMRatchetStep
	steps       []*KEMRatchetStep
	skippedKeys map[string]*skippedKeyEntry
	ratchetKP   *HybridKEMKeyPair
	// AD and signing key bytes are immutable after session creation;
	// included for completeness to guard against future drift.
	ad                       []byte
	initiatorSigningKeyBytes []byte
	responderSigningKeyBytes []byte
}

func (s *Session) snapshot() *ratchetSnapshot {
	rootKeyCopy := make([]byte, len(s.RootKey))
	copy(rootKeyCopy, s.RootKey)

	// Deep-copy CurrentStep (chains mutate their counter and root key).
	//
	// RemoteRatchetKey and EpochRatchetCT are copied as pointers, not values.
	// This is safe because HybridKEMPublicKey and HybridKEMCiphertext are
	// fixed-size [N]byte arrays — they cannot be mutated through a pointer
	// without reassigning the pointer itself. When a new ratchet step replaces
	// these fields in the live CurrentStep, the snapshot retains the old
	// pointers unaffected. If this code is ever changed to use mutable types
	// here, these must be deep-copied instead.
	stepCopy := &KEMRatchetStep{
		RemoteRatchetKey: s.CurrentStep.RemoteRatchetKey,
		EpochRatchetCT:   s.CurrentStep.EpochRatchetCT,
	}
	if s.CurrentStep.SendingChain != nil {
		sc := *s.CurrentStep.SendingChain
		stepCopy.SendingChain = &sc
	}
	if s.CurrentStep.ReceivingChain != nil {
		rc := *s.CurrentStep.ReceivingChain
		stepCopy.ReceivingChain = &rc
	}

	// Shallow-copy steps slice — we only need to restore the slice header.
	stepsCopy := make([]*KEMRatchetStep, len(s.Steps))
	copy(stepsCopy, s.Steps)

	// Shallow-copy skipped keys map — entries are immutable once written.
	skippedKeysCopy := make(map[string]*skippedKeyEntry, len(s.SkippedKeys))
	for k, v := range s.SkippedKeys {
		skippedKeysCopy[k] = v
	}

	adCopy := make([]byte, len(s.AD))
	copy(adCopy, s.AD)
	initiatorCopy := make([]byte, len(s.InitiatorSigningKeyBytes))
	copy(initiatorCopy, s.InitiatorSigningKeyBytes)
	responderCopy := make([]byte, len(s.ResponderSigningKeyBytes))
	copy(responderCopy, s.ResponderSigningKeyBytes)

	return &ratchetSnapshot{
		rootKey:                  rootKeyCopy,
		currentStep:              stepCopy,
		steps:                    stepsCopy,
		skippedKeys:              skippedKeysCopy,
		ratchetKP:                s.RatchetKP,
		ad:                       adCopy,
		initiatorSigningKeyBytes: initiatorCopy,
		responderSigningKeyBytes: responderCopy,
	}
}

func (s *Session) restore(snap *ratchetSnapshot) {
	s.RootKey = snap.rootKey
	s.CurrentStep = snap.currentStep
	s.Steps = snap.steps
	s.SkippedKeys = snap.skippedKeys
	s.RatchetKP = snap.ratchetKP
	s.AD = snap.ad
	s.InitiatorSigningKeyBytes = snap.initiatorSigningKeyBytes
	s.ResponderSigningKeyBytes = snap.responderSigningKeyBytes
}

// DecryptSignedMessage decrypts a received message after verifying its HMAC.
//
// Security ordering:
//  1. Snapshot session state (so we can roll back on auth failure).
//  2. Speculatively derive message keys (advances ratchet in the snapshot copy).
//  3. Verify HMAC over (AD || initiatorSigningKey || responderSigningKey || messageRaw).
//     AD = Encode(IKA) || Encode(IKB) per X3DH spec §3.3 — binds the MAC to
//     the specific session identity keys. Initiator and responder keys are
//     stable session roles so both sides compute the same input regardless of
//     who is currently sending.
//     messageRaw already contains the RatchetCT bytes (the MessageProtocol wire
//     format includes HasRatchetCT + RatchetCT verbatim), so no separate binding
//     of the KEM ciphertext is needed.
//  4. Only on HMAC success: commit the derived state.
//     On failure: restore the snapshot and return ErrHMACVerifyFailed.
//  5. Decrypt with AES-256-GCM (GCM tag is the last 16 bytes of CipherText).
func (s *Session) DecryptSignedMessage(msg *ParsedMessageSigned) ([]byte, error) {
	if msg.Message == nil || msg.MessageRaw == nil {
		return nil, fmt.Errorf("signed message missing fields")
	}
	if len(s.InitiatorSigningKeyBytes) == 0 || len(s.ResponderSigningKeyBytes) == 0 {
		return nil, ErrMissingSigningKey
	}

	incoming := &IncomingMessage{
		Ciphertext: msg.Message.CipherText,
		RatchetPub: msg.Message.SenderRatchetPub,
		RatchetCT:  msg.Message.RatchetCT,
		Counter:    int(msg.Message.Counter),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Step 1: snapshot — so we can roll back if HMAC fails.
	snap := s.snapshot()

	// Step 2: speculatively derive message keys, mutating session state.
	mk, err := s.deriveMessageKeysLocked(incoming)
	if err != nil {
		s.restore(snap)
		return nil, err
	}

	// Step 3: verify HMAC before any use of derived keys or decryption.
	//
	// Signed data layout: AD || initiatorSigningKey || responderSigningKey || messageRaw
	//
	// Initiator and responder roles are stable session properties, so both
	// sides compute the same byte string regardless of who is currently
	// encrypting. This avoids the Local/Remote perspective inversion bug
	// where sender and receiver would disagree on field order.
	//
	// messageRaw already contains RatchetCT verbatim (HasRatchetCT + bytes),
	// so no separate binding of the KEM ciphertext is needed.
	signedData := make([]byte, 0,
		len(s.AD)+len(s.InitiatorSigningKeyBytes)+len(s.ResponderSigningKeyBytes)+len(msg.MessageRaw))
	signedData = append(signedData, s.AD...)
	signedData = append(signedData, s.InitiatorSigningKeyBytes...)
	signedData = append(signedData, s.ResponderSigningKeyBytes...)
	signedData = append(signedData, msg.MessageRaw...)
	expected := hmacSHA256(mk.HMACKey, signedData)

	if subtle.ConstantTimeCompare(expected, msg.Signature) != 1 {
		// Roll back: unauthenticated input must not advance ratchet state.
		s.restore(snap)
		return nil, ErrHMACVerifyFailed
	}

	// Step 4: HMAC verified — state is committed (snapshot discarded).
	// Step 5: decrypt with AES-256-GCM (tag is included in CipherText).
	// s.AD is passed as GCM additional data — the decrypt will fail if the
	// ciphertext was produced in a different session (different identity keys).
	return AESGCMDecrypt(mk.AESKey, mk.Nonce, s.AD, msg.Message.CipherText)
}

func (s *Session) deriveMessageKeysLocked(msg *IncomingMessage) (*MessageKeys, error) {
	// Prune expired skipped keys.
	if s.SkippedKeyTTL > 0 {
		now := time.Now()
		for id, e := range s.SkippedKeys {
			if now.Sub(e.CachedAt) > s.SkippedKeyTTL {
				delete(s.SkippedKeys, id)
			}
		}
	}

	// Check for a cached skipped key (out-of-order delivery).
	skID := skippedKeyID(msg.RatchetPub, msg.Counter)
	if entry, ok := s.SkippedKeys[skID]; ok {
		delete(s.SkippedKeys, skID)
		return entry.Keys, nil
	}

	// Determine if this is a new ratchet key.
	needNewStep := false
	if s.CurrentStep.RemoteRatchetKey != nil {
		if !bytes.Equal(s.CurrentStep.RemoteRatchetKey[:], msg.RatchetPub[:]) {
			needNewStep = true
		}
	}

	if needNewStep {
		if s.CurrentStep.ReceivingChain != nil {
			// Cache any remaining out-of-order keys from the old epoch.
			// We cache up to maxOldEpochSkip ahead of the current chain counter
			// to allow late delivery of messages from the previous ratchet epoch.
			// We do NOT use MaxSkip here — that would speculatively pre-cache 1000
			// keys that were never sent, exhausting the global skipped key cache.
			oldTarget := s.CurrentStep.ReceivingChain.Counter + maxOldEpochSkip
			if err := s.cacheSkippedKeys(s.CurrentStep.RemoteRatchetKey, s.CurrentStep.ReceivingChain, oldTarget); err != nil && err != ErrSkippedKeyCapacity {
				return nil, err
			}
		}
		s.Steps = append(s.Steps, s.CurrentStep)
		if len(s.Steps) > maxRatchetStackSize {
			s.Steps = s.Steps[len(s.Steps)-maxRatchetStackSize:]
		}
		s.CurrentStep = &KEMRatchetStep{
			RemoteRatchetKey: msg.RatchetPub,
		}
	}

	if s.CurrentStep.ReceivingChain == nil {
		s.CurrentStep.RemoteRatchetKey = msg.RatchetPub
		if msg.RatchetCT == nil {
			return nil, fmt.Errorf("pqcratchet: ratchet step required but no KEM ciphertext in message")
		}
		chain, err := s.createReceivingChain(&s.RatchetKP.Private, msg.RatchetCT)
		if err != nil {
			return nil, err
		}
		s.CurrentStep.ReceivingChain = chain
	}

	// Validate counter.
	if msg.Counter < s.CurrentStep.ReceivingChain.Counter {
		return nil, ErrDuplicateMessage
	}
	if msg.Counter-s.CurrentStep.ReceivingChain.Counter > MaxSkip {
		return nil, ErrCounterTooLarge
	}

	if err := s.cacheSkippedKeys(msg.RatchetPub, s.CurrentStep.ReceivingChain, msg.Counter); err != nil {
		return nil, err
	}

	cipherKey, err := s.CurrentStep.ReceivingChain.Step()
	if err != nil {
		return nil, err
	}
	return DeriveMessageKeys(cipherKey)
}

func (s *Session) cacheSkippedKeys(ratchetPub *HybridKEMPublicKey, chain *SymmetricChain, target int) error {
	for chain.Counter < target {
		if len(s.SkippedKeys) >= MaxSkip {
			// Cache is full. Keys between chain.Counter and target-1 are lost.
			// Return a sentinel so callers can surface this to the application;
			// messages whose keys were not cached cannot be decrypted later.
			// This is a deliberate DoS defence: an unbounded cache is exploitable
			// by a sender who forces the receiver to store millions of skipped keys.
			return ErrSkippedKeyCapacity
		}
		cipherKey, err := chain.Step()
		if err != nil {
			return err
		}
		mk, err := DeriveMessageKeys(cipherKey)
		if err != nil {
			return err
		}
		s.SkippedKeys[skippedKeyID(ratchetPub, chain.Counter-1)] = &skippedKeyEntry{
			Keys:     mk,
			CachedAt: time.Now(),
		}
	}
	return nil
}

// skippedKeyID returns the cache key for a skipped message entry.
// Uses the first 32 bytes of the ratchet public key as the epoch discriminator.
//
// Security note: only 32 of 1216 bytes are used. For honest senders, all
// bytes are high-entropy random material and collision probability is
// negligible (~2^-128 for 32 bytes of uniform randomness). An adversary who
// crafts a public key matching the first 32 bytes of a prior ratchet key at
// a given counter would cause the wrong MessageKeys to be returned; the
// subsequent HMAC check would then fail and roll back state — no corruption,
// just a decryption failure. The full key is not used to avoid the allocation
// cost of hex.EncodeToString(pub[:]) = 2432 chars on the hot decrypt path.
func skippedKeyID(pub *HybridKEMPublicKey, counter int) string {
	return hex.EncodeToString(pub[:32]) + ":" + strconv.Itoa(counter)
}

// ToPreKeyMessageWire builds the PreKeyMessageWire struct from the X3DH result
// so it can be passed directly to MarshalPreKeyMessageWire.
// This is a convenience method to avoid field-by-field construction at the call site.
func (r *KEMInitiatorResult) ToPreKeyMessageWire(alice *Identity, bundle *PreKeyBundle) *PreKeyMessageWire {
	m := &PreKeyMessageWire{
		RegistrationID:     uint32(alice.ID),
		SignedPreKeyIndex:  uint32(bundle.SignedPreKeyIndex),
		OneTimePreKeyIndex: NoOneTimePreKey,
	}
	if bundle.OneTimePreKeyIndex >= 0 && r.CT4 != nil {
		m.OneTimePreKeyIndex = uint32(bundle.OneTimePreKeyIndex)
		m.HasCT4 = true
		copy(m.CT4[:], r.CT4[:])
	}
	copy(m.SigningPub[:], DSAPublicKeyBytes(alice.SigningKey.Public))
	copy(m.ExchangeKeySig[:], alice.ExchangeKeySignature)
	copy(m.ExchangePub[:], alice.ExchangeKey.Public[:])
	copy(m.BaseKey[:], r.EphemeralKP.Public[:])
	copy(m.CT1[:], r.CT1[:])
	copy(m.CT2[:], r.CT2[:])
	copy(m.InitiatorSig[:], r.InitiatorSig)
	return m
}
