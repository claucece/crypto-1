package elgamal

import (
	"io"

	"github.com/twtiger/crypto/curve"
)

// ElGamal is an instance of the ElGamal Cryptosystem
type ElGamal struct {
	Curve Curve
}

// Curve defines what curve functions are required for the ElGamal Cryptosystem
type Curve interface {
	curve.BasicCurve
	curve.PrecomputedMultiplier
	curve.PointCalculator
	curve.Decoder
}

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G curve.Point
	Q curve.Scalar
	Y curve.Point
}

// SecretKey represents an ElGamal private key.
type SecretKey struct {
	X curve.Scalar
}

// KeyPair represents an ElGamal key pair.
type KeyPair struct {
	Pub *PublicKey
	Sec *SecretKey
}

func (eg *ElGamal) secretKey(rand io.Reader) (*SecretKey, error) {
	x, err := eg.Curve.RandLongTermScalar(rand)
	if err != nil {
		return nil, err
	}
	return &SecretKey{x}, nil
}

// GenerateKeys generates a key pair of ElGamal keys.
func (eg *ElGamal) GenerateKeys(rand io.Reader) (*KeyPair, error) {
	sk, err := eg.secretKey(rand)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Pub: &PublicKey{
			G: eg.Curve.G(),
			Q: eg.Curve.Q(),
			Y: eg.Curve.PrecompScalarMul(sk.X),
		},
		Sec: sk,
	}, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// pair of integers. Errors can result from reading random.
func (eg *ElGamal) Encrypt(rand io.Reader, pub *PublicKey, message []byte) (c1, c2 curve.Point, err error) {
	k, err := eg.Curve.RandLongTermScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	// XXX: check the mod
	c1 = eg.Curve.PrecompScalarMul(k)
	// XXX: expose the s?
	s := eg.Curve.PointScalarMul(pub.Y, k)
	c2 = eg.Curve.AddPoints(s, eg.Curve.DecodePoint(message))
	return
}

// Decrypt takes two integers, resulting from an ElGamal encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid. Users should keep in mind that this is a padding
// oracle and thus, if exposed to an adaptive chosen ciphertext attack, can
// be used to break the cryptosystem.  See ``Chosen Ciphertext Attacks
// Against Protocols Based on the RSA Encryption Standard PKCS #1'', Daniel
// Bleichenbacher, Advances in Cryptology (Crypto '98).
func (eg *ElGamal) Decrypt(sec *SecretKey, c1, c2 curve.Point) []byte {
	s := eg.Curve.PointScalarMul(c1, sec.X)
	return eg.Curve.SubPoints(c2, s).Encode()
}
