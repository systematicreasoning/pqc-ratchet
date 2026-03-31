// Package pqcratchet implements a post-quantum variant of the Double Ratchet
// and X3DH key agreement protocols.
//
// # Algorithm choices
//
// This package replaces all classical asymmetric primitives with NIST PQC
// standards while keeping the symmetric ratchet (AES-256-GCM, HMAC-SHA-256,
// HKDF) unchanged — those are already quantum-safe.
//
//   - Signing (IdentityKey, PreKey signatures): ML-DSA-65 (FIPS 204)
//   - Key exchange (X3DH, KEM ratchet):          ML-KEM-768 (FIPS 203) + X25519 (hybrid)
//   - Symmetric encryption:                      AES-256-GCM (AEAD)
//   - MAC:                                        HMAC-SHA-256 (outer session MAC)
//   - KDF:                                        HKDF-SHA-256 (unchanged)
//
// # Hybrid key exchange
//
// The KEM ratchet and X3DH key agreement use a hybrid construction combining
// ML-KEM-768 and X25519. Both shared secrets are combined via HKDF:
//
//	SK = HKDF-SHA256(mlkem_ss || x25519_ss, salt, info)
//
// This provides security if either primitive is broken: the classical X25519
// protects against flawed PQC implementations, and ML-KEM protects against a
// future quantum adversary.
//
// # X3DH with KEMs
//
// The original X3DH protocol uses DH computations. Since ML-KEM is a KEM
// (encapsulate/decapsulate), not a DH primitive, the protocol is restructured
// while preserving the same forward secrecy and authentication properties.
//
// Alice (initiator) encapsulates against Bob's public keys:
//
//	(ct1, ss1) = KEM.Encap(SPK_B)              // signed pre-key → mutual auth + FS
//	(ct2, ss2) = KEM.Encap(IK_B.ex)            // identity exchange key → mutual auth
//	EK_A       = KEM.KeyGen()                  // ephemeral KEM keypair
//	SK = HKDF(0xFF×32 || ss1 || ss2)           // without OPK
//
//	With one-time pre-key:
//	(ct4, ss3) = KEM.Encap(OPK_B)             // one-time pre-key → forward secrecy
//	SK = HKDF(0xFF×32 || ss1 || ss2 || ss3)
//
//	Sent to Bob: IK_A || EK_A.pub || ct1 || ct2 [|| ct4] || Sig(IK_A.sig, transcript)
//
// Bob (responder) decapsulates:
//
//	ss1 = KEM.Decap(SPK_B.sk, ct1)
//	ss2 = KEM.Decap(IK_B.ex.sk, ct2)
//	[ss3 = KEM.Decap(OPK_B.sk, ct4)]
//	SK  = HKDF(0xFF×32 || ss1 || ss2 [|| ss3])
//
// Associated Data (per X3DH spec §3.3):
//
//	AD = Encode(IK_A.ex) || Encode(IK_B.ex)
//
// AD is mixed into every message HMAC to bind message authentication to the
// session identity keys.
//
// Authentication vs. deniability tradeoff:
//
// The original X3DH achieves deniability because DH computations are symmetric
// — anyone with the public keys could compute the same shared secret, so a
// transcript doesn't prove which party sent it. In this KEM-based variant,
// Alice must sign the transcript with ML-DSA-65 to authenticate herself, since
// KEMs don't provide the same implicit authentication as DH. This signature is
// non-repudiable: Alice cannot plausibly deny having sent the initial message.
// This is a deliberate tradeoff required by the PQC construction, not a bug.
// See X3DH spec §4.4 and §4.5 for the original deniability analysis.
//
// # KEM ratchet
//
// Each ratchet step generates a fresh ephemeral KEM keypair. The sender
// encapsulates against the receiver's current ratchet key; the resulting
// ciphertext is sent in the message header alongside the sender's new ratchet
// public key. The receiver decapsulates to derive the same shared secret, which
// feeds the root KDF.
//
// # Wire format
//
// KEM ciphertexts and public keys are substantially larger than their classical
// counterparts:
//
//	ML-KEM-768 public key:  1,184 bytes (vs 32 bytes for X25519)
//	ML-KEM-768 ciphertext:  1,088 bytes (vs 32 bytes for X25519)
//	ML-DSA-65 public key:   1,952 bytes (vs 32 bytes for Ed25519)
//	ML-DSA-65 signature:    3,309 bytes (vs 64 bytes for Ed25519)
//
// Hybrid keys and ciphertexts concatenate the PQC and classical components.
//
// # Compatibility
//
// This implementation is NOT wire-compatible with 2key-ratchet. It is a
// clean-break redesign sharing the same protocol structure but with entirely
// different wire formats and key types. Both ends must use this library.
//
// # Formal security properties
//
// This construction is an instantiation of the modular Double Ratchet framework
// of Alwen, Coretti, and Dodis (ACD19) [1], using a KEM-based Continuous Key
// Agreement (CKA) scheme in place of the DH-based ratchet. The composition
// theorem of ACD19 (Theorem 1) proves that any secure messaging scheme built
// from a secure CKA, a secure FS-AEAD, and a PRF-PRNG achieves:
//
//   - Forward security (FS): compromise of current state cannot recover keys
//     for messages sent before the last ratchet step.
//
//   - Post-compromise security (PCS): after a state compromise, security is
//     restored within ∆_SM rounds. For this implementation ∆_SM = 3, because
//     the ratchet keypair private key is retained until the next sending epoch
//     (∆_CKA = 1), matching the behaviour of Signal's deployed DH ratchet.
//     The ideal minimum ∆_SM = 2 is achievable with ∆_CKA = 0 by zeroing
//     RatchetKP.Private immediately after decapsulation, at the cost of a
//     more complex sending-epoch bootstrapping path.
//
//   - Immediate decryption: parties recover seamlessly if a message is
//     permanently lost. Out-of-order delivery is supported via EpochRatchetCT
//     (carried on every message) and the skipped-key cache (MaxSkip = 1000).
//
// The KEM-based CKA is secure under IND-CCA2 of the underlying KEM (ACD19
// Theorem 2). ML-KEM-768 is IND-CCA2 secure under the Module Learning With
// Errors (MLWE) assumption (FIPS 203). The hybrid construction additionally
// requires only one of ML-KEM-768 or X25519 to be secure.
//
// Collins, Riepel, and Tran (CRT24) [2] show that in the multi-session setting,
// KEM-based Double Ratchet admits a tight security reduction: the adversary's
// advantage against the messaging scheme is at most the advantage against the
// KEM, with no polynomial loss in the number of sessions. This tight bound holds
// for post-quantum KEMs including ML-KEM-768.
//
// The X3DH key agreement follows the structure of Hashimoto et al. [3] but
// uses ML-DSA-65 signatures rather than designated-verifier signatures, which
// provides authentication at the cost of deniability (see §4.5 of [4]).
//
// References:
//
//	[1] Alwen, Coretti, Dodis. "The Double Ratchet: Security Notions, Proofs,
//	    and Modularization for the Signal Protocol." EUROCRYPT 2019.
//	    https://eprint.iacr.org/2018/1037
//
//	[2] Collins, Riepel, Tran. "On the Tight Security of the Double Ratchet."
//	    ACM CCS 2024.
//	    https://eprint.iacr.org/2024/1625
//
//	[3] Hashimoto, Katsumata, Kwiatkowski, Prest. "An Efficient and Generic
//	    Construction for Signal's Handshake (X3DH): Post-Quantum, State Leakage
//	    Secure, and Deniable." PKC 2022. https://eprint.iacr.org/2021/616
//
//	[4] Marlinspike, Perrin. "The X3DH Key Agreement Protocol." Signal, 2016.
//	    https://signal.org/docs/specifications/x3dh/
//
//	[5] Marlinspike, Perrin. "The Double Ratchet Algorithm." Signal, 2016.
//	    https://signal.org/docs/specifications/doubleratchet/
//
//	[6] Kret, Schmidt. "The PQXDH Key Agreement Protocol." Signal, 2023.
//	    Signal's deployed PQ X3DH replacement. Hybrid (X25519 + ML-KEM) approach
//	    that preserves deniability but relies on classical hardness for auth.
//	    https://signal.org/docs/specifications/pqxdh/
//
//	[7] Brendel, Fiedler, Günther, Janson, Stebila. "Post-Quantum Asynchronous
//	    Deniable Key Exchange and the Signal Handshake." PKC 2022.
//	    Achieves PQ deniability via designated-verifier signatures.
//	    https://eprint.iacr.org/2021/769
//
//	[8] Collins, Huguenin-Dumittan, Nguyen, Rolin, Vaudenay. "K-Waay: Fast and
//	    Deniable Post-Quantum X3DH without Ring Signatures." ASIACCS 2025.
//	    Most efficient deniable PQ X3DH construction to date.
//	    https://eprint.iacr.org/2024/120
package pqcratchet

import "errors"

// Protocol errors.
var (
	ErrInvalidSignature  = errors.New("pqcratchet: invalid signature")
	ErrDecryptionFailed  = errors.New("pqcratchet: decryption failed")
	ErrBadPadding        = errors.New("pqcratchet: invalid PKCS7 padding")
	ErrDuplicateMessage  = errors.New("pqcratchet: duplicate message counter")
	ErrCounterTooLarge   = errors.New("pqcratchet: message counter exceeds max skip")
	ErrHMACVerifyFailed  = errors.New("pqcratchet: HMAC verification failed")
	ErrNoRatchetKey      = errors.New("pqcratchet: no remote ratchet key set")
	ErrMissingSigningKey  = errors.New("pqcratchet: session missing signing keys for HMAC verification")
	ErrSkippedKeyCapacity = errors.New("pqcratchet: skipped key cache full — some out-of-order messages may be unrecoverable")
)

// MaxSkip is the maximum number of message keys to cache for out-of-order delivery.
const MaxSkip = 1000

// maxRatchetStackSize caps the number of retained KEMRatchetSteps.
const maxRatchetStackSize = 20

// maxOldEpochSkip is the maximum number of keys to cache from a previous ratchet
// epoch when a new epoch is detected. This bounds the speculative pre-caching of
// old-epoch out-of-order messages without draining the global MaxSkip budget.
const maxOldEpochSkip = 50

// Info labels for HKDF, per X3DH spec §2.1 ("an ASCII string identifying
// the application"). Prefixed with the package name and version for
// cross-system domain separation.
//
// Declared as fixed-size byte arrays so that the underlying memory cannot
// be mutated via a slice header (unlike []byte, a [N]byte cannot be extended
// via append and its address cannot be passed to a function expecting a
// mutable []byte without an explicit copy). Use label[:] at call sites.
//
// infoHybridKEM is also used inside Encapsulate/Decapsulate — interop
// implementers must use the same string.
const (
	_infoKEMInit     = "pqcratchet/v1/KEMInit"
	_infoRatchet     = "pqcratchet/v1/Ratchet"
	_infoMessageKeys = "pqcratchet/v1/MessageKeys"
	_infoHybridKEM   = "pqcratchet/v1/HybridKEM"
)

// infoSlices are the canonical []byte forms of the info constants.
// They are initialised once and never modified.
var (
	infoKEMInit     = []byte(_infoKEMInit)
	infoRatchet     = []byte(_infoRatchet)
	infoMessageKeys = []byte(_infoMessageKeys)
	infoHybridKEM   = []byte(_infoHybridKEM)
)

// Chain KDF diversifiers for the symmetric ratchet.
// Declared as fixed-size arrays to prevent mutation: unlike []byte, an array
// cannot be extended via append and individual bytes cannot be changed through
// a slice header. Convert to []byte at the call site with cipherKeyInput[:].
var (
	cipherKeyKDFInput = [1]byte{0x01} // derives the cipher key for this chain position
	rootKeyKDFInput   = [1]byte{0x02} // derives the next chain key
)
