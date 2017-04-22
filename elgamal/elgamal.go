package elgamal

import (
	"io"

	"github.com/twtiger/crypto/curve"
)

// ElGamal is an instance of the ElGamal Cryptosystem
type ElGamal struct {
	curve curve.Curve
}

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	Y curve.Point
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	X curve.Scalar
}

// KeyPair represents an ElGamal key pair.
type KeyPair struct {
	Pub  *PublicKey
	Priv *PrivateKey
}

func (eg *ElGamal) derivePrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err error

	priv.X, err = eg.curve.RandLongTermScalar(rand)
	if err != nil {
		return nil, err
	}

	return priv, err
}

// GenerateKeys generates a key pair of ElGamal keys.
func (eg *ElGamal) GenerateKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.Priv, err = eg.derivePrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.Pub = &PublicKey{}
	keyPair.Pub.Y = eg.curve.PrecompScalarMul(keyPair.Priv.X)

	return keyPair, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// pair of integers. Errors can result from reading random.
func (eg *ElGamal) Encrypt(rand io.Reader, pub *PublicKey, message []byte) (c1, c2 curve.Point, err error) {
	m := eg.curve.DecodePoint(message)
	k, err := eg.curve.RandLongTermScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	// XXX: check the mod
	c1 = eg.curve.PrecompScalarMul(k)
	// XXX: expose the s?
	s := eg.curve.PointScalarMul(pub.Y, k)
	c2 = eg.curve.Add(s, m)
	return
}

// Decrypt takes two integers, resulting from an ElGamal encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid. Users should keep in mind that this is a padding
// oracle and thus, if exposed to an adaptive chosen ciphertext attack, can
// be used to break the cryptosystem.  See ``Chosen Ciphertext Attacks
// Against Protocols Based on the RSA Encryption Standard PKCS #1'', Daniel
// Bleichenbacher, Advances in Cryptology (Crypto '98).
func (eg *ElGamal) Decrypt(priv *PrivateKey, c1, c2 curve.Point) []byte {
	s := eg.curve.PointScalarMul(c1, priv.X)
	m := eg.curve.Sub(c2, s)
	msg := m.Encode()
	return msg
}
