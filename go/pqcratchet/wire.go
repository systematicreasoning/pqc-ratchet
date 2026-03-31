package pqcratchet

// wire.go defines the binary wire format for PQC-ratchet protocol messages.
//
// Rather than protobuf (which requires code generation and adds a dependency),
// we use a simple length-prefixed binary format. Every variable-length field
// is prefixed with a 4-byte big-endian uint32 length. Fixed-size fields are
// written raw.
//
// All message types begin with a 1-byte version field. The current version is
// WireVersion (0x01). Parsers must reject messages with unknown versions.
//
// # Message types
//
// PreKeyBundle (server → client on connection):
//
//	[1]                   Version (0x01)
//	[4]                   RegistrationID
//	[4]                   SignedPreKeyIndex
//	[DSAPublicKeySize]    SigningPubKey
//	[DSASignatureSize]    ExchangeKeySig   (ML-DSA sig over ExchangePubKey)
//	[HybridPublicKeySize] ExchangePubKey
//	[HybridPublicKeySize] SignedPreKeyPub
//	[DSASignatureSize]    SignedPreKeySig
//	[1]                   HasOneTimePreKey (0x00 or 0x01)
//	[HybridPublicKeySize] OneTimePreKeyPub (only if HasOneTimePreKey==1)
//	[4]                   OneTimePreKeyIndex (only if HasOneTimePreKey==1)
//
// PreKeyMessage (initiator → responder):
//
//	[1]                    Version (0x01)
//	[4]                    RegistrationID
//	[4]                    SignedPreKeyIndex
//	[4]                    OneTimePreKeyIndex (-1 as 0xFFFFFFFF if none)
//	[DSAPublicKeySize]     SigningPubKey
//	[DSASignatureSize]     ExchangeKeySig
//	[HybridPublicKeySize]  ExchangePubKey
//	[HybridPublicKeySize]  BaseKey           (EK_A.pub)
//	[HybridCiphertextSize] CT1
//	[HybridCiphertextSize] CT2
//	[1]                    HasCT4
//	[HybridCiphertextSize] CT4 (only if HasCT4==1)
//	[DSASignatureSize]     InitiatorSig      (ML-DSA sig over X3DH transcript)
//	[4]                    SignedMessageLen  (0 if no bundled message)
//	[...]                  SignedMessageBytes
//
// MessageProtocol (per-message, inside MessageSignedProtocol):
//
//	[4]                    Counter
//	[HybridPublicKeySize]  SenderRatchetPub
//	[1]                    HasRatchetCT      (1 if KEM ratchet step occurred OR
//	                                          if this is a non-first message in
//	                                          an epoch carrying EpochRatchetCT
//	                                          for out-of-order delivery support)
//	[HybridCiphertextSize] RatchetCT (only if HasRatchetCT==1)
//	[4]                    CiphertextLen
//	[...]                  Ciphertext
//
// Note: EpochRatchetCT is carried on every message in a sending epoch, not
// just the first. This allows any message to bootstrap the receiver's chain
// regardless of arrival order. The cost is 1120 extra bytes per non-first
// message in an epoch.
//
// MessageSignedProtocol (outer envelope):
//
//	[1]   Version (0x01)
//	[32]  Signature  (HMAC-SHA-256, 32 bytes)
//	[4]   MessageLen
//	[...] MessageBytes (serialised MessageProtocol)
//
// # Message authentication (HMAC)
//
// The 32-byte Signature in MessageSignedProtocol is:
//
//	HMAC-SHA-256(messageKey, AD || initiatorSigKey || responderSigKey || MessageBytes)
//
// where:
//   - AD = Encode(IK_A.ex) || Encode(IK_B.ex)  — X3DH associated data per spec §3.3,
//     binding the MAC to the specific session identity keys
//   - initiatorSigKey = Alice's ML-DSA-65 signing public key bytes
//   - responderSigKey = Bob's ML-DSA-65 signing public key bytes
//
// Both sides use the same stable initiator/responder roles, so the byte string
// is identical regardless of who is currently sending.
//
// # KDF constants for interop
//
// All HKDF operations use SHA-256. The info strings are (for interop reference):
//
//	Session key derivation:  "pqcratchet/v1/KEMInit"
//	Ratchet step KDF:        "pqcratchet/v1/Ratchet"
//	Message key derivation:  "pqcratchet/v1/MessageKeys"
//	Hybrid KEM combiner:     "pqcratchet/v1/HybridKEM"  ← used inside every Encap/Decap

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WireVersion is the current protocol wire format version.
// Increment on any breaking wire format change.
const WireVersion = byte(0x01)

// maxCiphertextSize is the maximum allowed GCM output length (plaintext + 16-byte tag)
// in a message. Prevents OOM allocation from untrusted length fields. The effective
// maximum plaintext is maxCiphertextSize - AESGCMTagSize (16 bytes).
const maxCiphertextSize = 1 << 20 // 1 MB

// maxSignedMessageSize is the maximum bundled signed message size.
const maxSignedMessageSize = maxCiphertextSize + HybridCiphertextSize + HybridPublicKeySize + 512

// ─── ParsedMessageProtocol ────────────────────────────────────────────────────

// ParsedMessageProtocol holds a decoded inner message.
type ParsedMessageProtocol struct {
	Counter          uint32
	SenderRatchetPub *HybridKEMPublicKey
	RatchetCT        *HybridKEMCiphertext // nil if no ratchet step
	CipherText       []byte
}

// ParsedMessageSigned holds a decoded outer signed envelope.
type ParsedMessageSigned struct {
	Signature  []byte                 // 32 bytes (HMAC-SHA-256)
	Message    *ParsedMessageProtocol
	MessageRaw []byte // raw bytes of the inner message (for HMAC verification)
}

// ─── PreKeyBundle wire ────────────────────────────────────────────────────────

// BundleWire is the serialisable form of a PreKeyBundle.
type BundleWire struct {
	RegistrationID    uint32
	SignedPreKeyIndex uint32
	SigningPub        [DSAPublicKeySize]byte
	ExchangeKeySig    [DSASignatureSize]byte
	ExchangePub       [HybridPublicKeySize]byte
	SignedPreKeyPub   [HybridPublicKeySize]byte
	SignedPreKeySig   [DSASignatureSize]byte
	HasOneTimePreKey  bool
	OneTimePreKeyPub  [HybridPublicKeySize]byte
	OneTimePreKeyIndex uint32
}

// MarshalBundleWire serialises a BundleWire to bytes.
func MarshalBundleWire(b *BundleWire) []byte {
	var buf []byte
	buf = append(buf, WireVersion)
	buf = appendUint32(buf, b.RegistrationID)
	buf = appendUint32(buf, b.SignedPreKeyIndex)
	buf = append(buf, b.SigningPub[:]...)
	buf = append(buf, b.ExchangeKeySig[:]...)
	buf = append(buf, b.ExchangePub[:]...)
	buf = append(buf, b.SignedPreKeyPub[:]...)
	buf = append(buf, b.SignedPreKeySig[:]...)
	if b.HasOneTimePreKey {
		buf = append(buf, 0x01)
		buf = append(buf, b.OneTimePreKeyPub[:]...)
		buf = appendUint32(buf, b.OneTimePreKeyIndex)
	} else {
		buf = append(buf, 0x00)
	}
	return buf
}

// UnmarshalBundleWire deserialises a BundleWire from r.
func UnmarshalBundleWire(r io.Reader) (*BundleWire, error) {
	ver := make([]byte, 1)
	if err := readFull(r, ver); err != nil {
		return nil, fmt.Errorf("bundle: version: %w", err)
	}
	if ver[0] != WireVersion {
		return nil, fmt.Errorf("bundle: unsupported wire version 0x%02x (want 0x%02x)", ver[0], WireVersion)
	}
	b := &BundleWire{}
	var err error
	if b.RegistrationID, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("bundle: registrationID: %w", err)
	}
	if b.SignedPreKeyIndex, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("bundle: signedPreKeyIndex: %w", err)
	}
	if err = readFull(r, b.SigningPub[:]); err != nil {
		return nil, fmt.Errorf("bundle: signingPub: %w", err)
	}
	if err = readFull(r, b.ExchangeKeySig[:]); err != nil {
		return nil, fmt.Errorf("bundle: exchangeKeySig: %w", err)
	}
	if err = readFull(r, b.ExchangePub[:]); err != nil {
		return nil, fmt.Errorf("bundle: exchangePub: %w", err)
	}
	if err = readFull(r, b.SignedPreKeyPub[:]); err != nil {
		return nil, fmt.Errorf("bundle: signedPreKeyPub: %w", err)
	}
	if err = readFull(r, b.SignedPreKeySig[:]); err != nil {
		return nil, fmt.Errorf("bundle: signedPreKeySig: %w", err)
	}
	flag := make([]byte, 1)
	if err = readFull(r, flag); err != nil {
		return nil, fmt.Errorf("bundle: hasOneTimePreKey: %w", err)
	}
	if flag[0] == 0x01 {
		b.HasOneTimePreKey = true
		if err = readFull(r, b.OneTimePreKeyPub[:]); err != nil {
			return nil, fmt.Errorf("bundle: oneTimePreKeyPub: %w", err)
		}
		if b.OneTimePreKeyIndex, err = readUint32(r); err != nil {
			return nil, fmt.Errorf("bundle: oneTimePreKeyIndex: %w", err)
		}
	}
	return b, nil
}

// ParseBundleWire converts a BundleWire into a PreKeyBundle after signature
// verification. Returns an error if any signature is invalid.
func ParseBundleWire(b *BundleWire) (*PreKeyBundle, error) {
	sigPub, err := ParseDSAPublicKey(b.SigningPub[:])
	if err != nil {
		return nil, fmt.Errorf("parse signing pub: %w", err)
	}

	// Verify exchange key signature.
	if !Verify(sigPub, b.ExchangePub[:], b.ExchangeKeySig[:]) {
		return nil, ErrInvalidSignature
	}
	// Verify signed pre-key signature.
	if !Verify(sigPub, b.SignedPreKeyPub[:], b.SignedPreKeySig[:]) {
		return nil, ErrInvalidSignature
	}

	var exPub HybridKEMPublicKey
	var spkPub HybridKEMPublicKey
	copy(exPub[:], b.ExchangePub[:])
	copy(spkPub[:], b.SignedPreKeyPub[:])

	bundle := &PreKeyBundle{
		RegistrationID:         int(b.RegistrationID),
		IdentitySigningPub:     sigPub,
		IdentitySigningPubBytes: b.SigningPub[:],
		IdentityExchangePub:    &exPub,
		SignedPreKeyPub:        &spkPub,
		SignedPreKeyIndex:      int(b.SignedPreKeyIndex),
		OneTimePreKeyIndex:     -1,
	}
	if b.HasOneTimePreKey {
		var opkPub HybridKEMPublicKey
		copy(opkPub[:], b.OneTimePreKeyPub[:])
		bundle.OneTimePreKeyPub = &opkPub
		bundle.OneTimePreKeyIndex = int(b.OneTimePreKeyIndex)
	}
	return bundle, nil
}

// MakeBundleWire builds a BundleWire from an Identity and signed pre-key index.
func MakeBundleWire(id *Identity, spkIndex int, opkIndex int) (*BundleWire, error) {
	if spkIndex >= len(id.SignedPreKeys) {
		return nil, fmt.Errorf("signed pre-key index %d out of range", spkIndex)
	}
	sigPubBytes := DSAPublicKeyBytes(id.SigningKey.Public)

	b := &BundleWire{
		RegistrationID:   uint32(id.ID),
		SignedPreKeyIndex: uint32(spkIndex),
	}
	copy(b.SigningPub[:], sigPubBytes)
	copy(b.ExchangeKeySig[:], id.ExchangeKeySignature)
	copy(b.ExchangePub[:], id.ExchangeKey.Public[:])
	copy(b.SignedPreKeyPub[:], id.SignedPreKeys[spkIndex].Public[:])
	copy(b.SignedPreKeySig[:], id.SignedPreKeySigs[spkIndex])

	if opkIndex >= 0 && opkIndex < len(id.PreKeys) && id.PreKeys[opkIndex] != nil {
		b.HasOneTimePreKey = true
		copy(b.OneTimePreKeyPub[:], id.PreKeys[opkIndex].Public[:])
		b.OneTimePreKeyIndex = uint32(opkIndex)
	}
	return b, nil
}

// ─── PreKeyMessage wire ───────────────────────────────────────────────────────

// PreKeyMessageWire is the serialisable form of a PreKeyMessage.
type PreKeyMessageWire struct {
	RegistrationID     uint32
	SignedPreKeyIndex  uint32
	OneTimePreKeyIndex uint32 // 0xFFFFFFFF means none
	SigningPub         [DSAPublicKeySize]byte
	ExchangeKeySig     [DSASignatureSize]byte
	ExchangePub        [HybridPublicKeySize]byte
	BaseKey            [HybridPublicKeySize]byte
	CT1                [HybridCiphertextSize]byte
	CT2                [HybridCiphertextSize]byte
	HasCT4             bool
	CT4                [HybridCiphertextSize]byte
	// InitiatorSig is Alice's ML-DSA-65 signature over the X3DH transcript.
	// Must be DSASignatureSize bytes. Verified by ParsePreKeyMessageWire.
	InitiatorSig       [DSASignatureSize]byte
	SignedMessageBytes []byte // nil if no bundled message
}

const noOneTimePreKey = uint32(0xFFFFFFFF)

// MarshalPreKeyMessageWire serialises a PreKeyMessageWire.
func MarshalPreKeyMessageWire(m *PreKeyMessageWire) []byte {
	var buf []byte
	buf = append(buf, WireVersion)
	buf = appendUint32(buf, m.RegistrationID)
	buf = appendUint32(buf, m.SignedPreKeyIndex)
	buf = appendUint32(buf, m.OneTimePreKeyIndex)
	buf = append(buf, m.SigningPub[:]...)
	buf = append(buf, m.ExchangeKeySig[:]...)
	buf = append(buf, m.ExchangePub[:]...)
	buf = append(buf, m.BaseKey[:]...)
	buf = append(buf, m.CT1[:]...)
	buf = append(buf, m.CT2[:]...)
	if m.HasCT4 {
		buf = append(buf, 0x01)
		buf = append(buf, m.CT4[:]...)
	} else {
		buf = append(buf, 0x00)
	}
	buf = append(buf, m.InitiatorSig[:]...)
	buf = appendUint32(buf, uint32(len(m.SignedMessageBytes)))
	buf = append(buf, m.SignedMessageBytes...)
	return buf
}

// UnmarshalPreKeyMessageWire deserialises a PreKeyMessageWire from r.
func UnmarshalPreKeyMessageWire(r io.Reader) (*PreKeyMessageWire, error) {
	ver := make([]byte, 1)
	if err := readFull(r, ver); err != nil {
		return nil, fmt.Errorf("preKeyMsg: version: %w", err)
	}
	if ver[0] != WireVersion {
		return nil, fmt.Errorf("preKeyMsg: unsupported wire version 0x%02x (want 0x%02x)", ver[0], WireVersion)
	}
	m := &PreKeyMessageWire{}
	var err error
	if m.RegistrationID, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("preKeyMsg: registrationID: %w", err)
	}
	if m.SignedPreKeyIndex, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("preKeyMsg: signedPreKeyIndex: %w", err)
	}
	if m.OneTimePreKeyIndex, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("preKeyMsg: oneTimePreKeyIndex: %w", err)
	}
	if err = readFull(r, m.SigningPub[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: signingPub: %w", err)
	}
	if err = readFull(r, m.ExchangeKeySig[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: exchangeKeySig: %w", err)
	}
	if err = readFull(r, m.ExchangePub[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: exchangePub: %w", err)
	}
	if err = readFull(r, m.BaseKey[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: baseKey: %w", err)
	}
	if err = readFull(r, m.CT1[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: CT1: %w", err)
	}
	if err = readFull(r, m.CT2[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: CT2: %w", err)
	}
	flag := make([]byte, 1)
	if err = readFull(r, flag); err != nil {
		return nil, fmt.Errorf("preKeyMsg: hasCT4: %w", err)
	}
	if flag[0] == 0x01 {
		m.HasCT4 = true
		if err = readFull(r, m.CT4[:]); err != nil {
			return nil, fmt.Errorf("preKeyMsg: CT4: %w", err)
		}
	}
	if err = readFull(r, m.InitiatorSig[:]); err != nil {
		return nil, fmt.Errorf("preKeyMsg: initiatorSig: %w", err)
	}
	msgLen, err := readUint32(r)
	if err != nil {
		return nil, fmt.Errorf("preKeyMsg: signedMessageLen: %w", err)
	}
	if msgLen > maxSignedMessageSize {
		return nil, fmt.Errorf("preKeyMsg: bundled message length %d exceeds maximum %d", msgLen, maxSignedMessageSize)
	}
	if msgLen > 0 {
		m.SignedMessageBytes = make([]byte, msgLen)
		if err = readFull(r, m.SignedMessageBytes); err != nil {
			return nil, fmt.Errorf("preKeyMsg: signedMessage: %w", err)
		}
	}
	return m, nil
}

// ParsePreKeyMessageWire verifies exchange key signature and converts a
// PreKeyMessageWire into a PreKeyMessage. The X3DH transcript signature
// (InitiatorSig) is verified later by AuthenticateB, which has access to
// all the ciphertexts needed to reconstruct the transcript.
func ParsePreKeyMessageWire(m *PreKeyMessageWire) (*PreKeyMessage, error) {
	sigPub, err := ParseDSAPublicKey(m.SigningPub[:])
	if err != nil {
		return nil, fmt.Errorf("parse signing pub: %w", err)
	}
	// Verify exchange key signature — proves the exchange key belongs to the
	// party holding the signing private key.
	if !Verify(sigPub, m.ExchangePub[:], m.ExchangeKeySig[:]) {
		return nil, ErrInvalidSignature
	}

	var exPub, baseKey HybridKEMPublicKey
	copy(exPub[:], m.ExchangePub[:])
	copy(baseKey[:], m.BaseKey[:])

	var ct1, ct2 HybridKEMCiphertext
	copy(ct1[:], m.CT1[:])
	copy(ct2[:], m.CT2[:])

	msg := &PreKeyMessage{
		RegistrationID:          int(m.RegistrationID),
		SignedPreKeyIndex:        int(m.SignedPreKeyIndex),
		OneTimePreKeyIndex:      -1,
		IdentitySigningPub:      sigPub,
		IdentitySigningPubBytes: m.SigningPub[:],
		IdentityExchangePub:     &exPub,
		BaseKey:                 &baseKey,
		CT1:                     &ct1,
		CT2:                     &ct2,
		InitiatorSig:            m.InitiatorSig[:],
	}
	if m.OneTimePreKeyIndex != noOneTimePreKey {
		msg.OneTimePreKeyIndex = int(m.OneTimePreKeyIndex)
	}
	if m.HasCT4 {
		var ct4 HybridKEMCiphertext
		copy(ct4[:], m.CT4[:])
		msg.CT4 = &ct4
	}
	if len(m.SignedMessageBytes) > 0 {
		sm, err := UnmarshalSignedMessage(m.SignedMessageBytes)
		if err != nil {
			return nil, fmt.Errorf("parse bundled signed message: %w", err)
		}
		msg.SignedMessage = sm
	}
	return msg, nil
}

// ─── MessageProtocol wire ─────────────────────────────────────────────────────

// MarshalMessageProtocol serialises a ParsedMessageProtocol.
func MarshalMessageProtocol(m *ParsedMessageProtocol) []byte {
	var buf []byte
	buf = appendUint32(buf, m.Counter)
	buf = append(buf, m.SenderRatchetPub[:]...)
	if m.RatchetCT != nil {
		buf = append(buf, 0x01)
		buf = append(buf, m.RatchetCT[:]...)
	} else {
		buf = append(buf, 0x00)
	}
	buf = appendUint32(buf, uint32(len(m.CipherText)))
	buf = append(buf, m.CipherText...)
	return buf
}

// UnmarshalMessageProtocol deserialises a ParsedMessageProtocol from b.
func UnmarshalMessageProtocol(b []byte) (*ParsedMessageProtocol, error) {
	r := newReader(b)
	m := &ParsedMessageProtocol{}
	var err error
	if m.Counter, err = readUint32(r); err != nil {
		return nil, fmt.Errorf("msg: counter: %w", err)
	}
	var ratchetPub HybridKEMPublicKey
	if err = readFull(r, ratchetPub[:]); err != nil {
		return nil, fmt.Errorf("msg: ratchetPub: %w", err)
	}
	m.SenderRatchetPub = &ratchetPub
	flag := make([]byte, 1)
	if err = readFull(r, flag); err != nil {
		return nil, fmt.Errorf("msg: hasRatchetCT: %w", err)
	}
	if flag[0] == 0x01 {
		var ratchetCT HybridKEMCiphertext
		if err = readFull(r, ratchetCT[:]); err != nil {
			return nil, fmt.Errorf("msg: ratchetCT: %w", err)
		}
		m.RatchetCT = &ratchetCT
	}
	ctLen, err := readUint32(r)
	if err != nil {
		return nil, fmt.Errorf("msg: ciphertextLen: %w", err)
	}
	if ctLen > maxCiphertextSize {
		return nil, fmt.Errorf("msg: ciphertext length %d exceeds maximum %d", ctLen, maxCiphertextSize)
	}
	m.CipherText = make([]byte, ctLen)
	if err = readFull(r, m.CipherText); err != nil {
		return nil, fmt.Errorf("msg: ciphertext: %w", err)
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("msg: %d unexpected trailing bytes", r.remaining())
	}
	return m, nil
}

// ─── MessageSignedProtocol wire ───────────────────────────────────────────────

// MarshalSignedMessage serialises a signed message envelope.
//
// Signed data layout: AD || initiatorSigKey || responderSigKey || inner
//
// Initiator and responder keys are stable session roles (Alice always initiator,
// Bob always responder), so both sides compute the same byte string regardless
// of who is currently sending. This avoids a Local/Remote perspective inversion
// where sender and receiver would disagree on field order.
//
// AD is the X3DH Associated Data (Encode(IKA) || Encode(IKB)), binding the MAC
// to the specific session identity keys per X3DH spec §3.3.
//
// Signature is 32 bytes (HMAC-SHA-256). The version byte is prepended for
// future protocol negotiation.
func MarshalSignedMessage(inner []byte, hmacKey, ad, initiatorSigKey, responderSigKey []byte) []byte {
	signedData := make([]byte, 0, len(ad)+len(initiatorSigKey)+len(responderSigKey)+len(inner))
	signedData = append(signedData, ad...)
	signedData = append(signedData, initiatorSigKey...)
	signedData = append(signedData, responderSigKey...)
	signedData = append(signedData, inner...)
	sig := hmacSHA256(hmacKey, signedData)

	var buf []byte
	buf = append(buf, WireVersion)
	buf = append(buf, sig...) // 32 bytes
	buf = appendUint32(buf, uint32(len(inner)))
	buf = append(buf, inner...)
	return buf
}

// UnmarshalSignedMessage deserialises a signed message envelope from b.
// Returns ErrHMACVerifyFailed if the HMAC does not match; the session
// DecryptSignedMessage method handles HMAC verification after key derivation.
func UnmarshalSignedMessage(b []byte) (*ParsedMessageSigned, error) {
	if len(b) < 1+32+4 {
		return nil, fmt.Errorf("signedMsg: too short")
	}
	if b[0] != WireVersion {
		return nil, fmt.Errorf("signedMsg: unsupported wire version 0x%02x (want 0x%02x)", b[0], WireVersion)
	}
	b = b[1:]

	sig := make([]byte, 32)
	copy(sig, b[:32])
	b = b[32:]

	msgLen := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < msgLen {
		return nil, fmt.Errorf("signedMsg: message truncated")
	}
	msgRaw := b[:msgLen]
	if uint32(len(b)) != msgLen {
		return nil, fmt.Errorf("signedMsg: %d unexpected trailing bytes", uint32(len(b))-msgLen)
	}

	msg, err := UnmarshalMessageProtocol(msgRaw)
	if err != nil {
		return nil, err
	}

	rawCopy := make([]byte, len(msgRaw))
	copy(rawCopy, msgRaw)

	return &ParsedMessageSigned{
		Signature:  sig,
		Message:    msg,
		MessageRaw: rawCopy,
	}, nil
}

// ─── Binary helpers ───────────────────────────────────────────────────────────

func appendUint32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint32(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

// byteReader wraps a []byte to implement io.Reader.
type byteReader struct {
	b []byte
	i int
}

func newReader(b []byte) *byteReader {
	return &byteReader{b: b}
}

func (r *byteReader) Read(p []byte) (n int, err error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n = copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func (r *byteReader) remaining() int {
	return len(r.b) - r.i
}
