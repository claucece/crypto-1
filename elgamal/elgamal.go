package elgamal

import (
	"io"

	"github.com/twstrike/ed448"
	"github.com/twtiger/crypto/utils"
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G ed448.Point
	Q ed448.Scalar
	Y ed448.Point
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	X ed448.Scalar
}

// KeyPair represents an ElGamal key pair.
type KeyPair struct {
	Pub  *PublicKey
	Priv *PrivateKey
}

func derivePrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err error

	priv.X, err = utils.RandLongTermScalar(rand)
	if err != nil {
		return nil, err
	}

	return priv, err
}

// GenerateKeys generates a key pair of ElGamal keys.
func GenerateKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.Priv, err = derivePrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.Pub = &PublicKey{}
	keyPair.Pub.G = ed448.BasePoint
	keyPair.Pub.Q = ed448.ScalarQ
	keyPair.Pub.Y = ed448.PrecomputedScalarMul(keyPair.Priv.X)

	return keyPair, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// pair of integers. Errors can result from reading random.
func Encrypt(rand io.Reader, pub *PublicKey, message []byte) (c1, c2 ed448.Point, err error) {
	m := ed448.NewPointFromBytes()
	m.Decode(message, false)

	k, err := utils.RandLongTermScalar(rand)
	if err != nil {
		return nil, nil, err
	}

	// XXX: check the mod
	c1 = ed448.PrecomputedScalarMul(k)
	// XXX: expose the s?
	s := ed448.PointScalarMul(pub.Y, k)

	c2 = ed448.NewPointFromBytes()
	c2.Add(s, m)

	return
}

// Decrypt takes two integers, resulting from an ElGamal encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid. Users should keep in mind that this is a padding
// oracle and thus, if exposed to an adaptive chosen ciphertext attack, can
// be used to break the cryptosystem.  See ``Chosen Ciphertext Attacks
// Against Protocols Based on the RSA Encryption Standard PKCS #1'', Daniel
// Bleichenbacher, Advances in Cryptology (Crypto '98).
func Decrypt(priv *PrivateKey, c1, c2 ed448.Point) []byte {
	s := ed448.PointScalarMul(c1, priv.X)
	m := ed448.NewPointFromBytes()
	m.Sub(c2, s)

	msg := m.Encode()

	return msg
}
