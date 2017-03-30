package elgamal

import (
	"io"

	"github.com/twstrike/ed448"
	// XXX: find a way to do this
	. "github.com/twtiger/crypto/utils"
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G ed448.Point
	Q ed448.Scalar
	H ed448.Point
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

func deriveElGamalPrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err error

	priv.X, err = RandLongTermScalar(rand)

	return priv, err
}

func deriveElGamalKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.Priv, err = deriveElGamalPrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.Pub = &PublicKey{}
	keyPair.Pub.G = ed448.BasePoint
	keyPair.Pub.Q = ed448.ScalarQ
	keyPair.Pub.H = ed448.PrecomputedScalarMul(keyPair.Priv.X)

	return keyPair, nil
}
