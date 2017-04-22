package cramershoup

import (
	"errors"
	"io"

	"github.com/twtiger/crypto/curve"
	"github.com/twtiger/crypto/utils"
)

// CramerShoup instantiates a Cramer-Shoup system with a specific elliptic curve
type CramerShoup struct {
	Curve Curve
}

// Curve defines what curve functions are required for the Cramer-Shoup Cryptosystem
type Curve interface {
	curve.BasicCurve
	curve.PointDoubleScalarMultiplier
	curve.PointCalculator
	curve.PointComparer
	curve.Decoder
}

// PublicKey represents a Cramer-Shoup public key.
type PublicKey struct {
	C, D, H curve.Point
}

// PrivateKey represents a Cramer-Shoup private key.
type PrivateKey struct {
	X1, X2, Y1, Y2, Z curve.Scalar
}

// KeyPair represents a Cramer-Shoup key pair.
type KeyPair struct {
	Pub  *PublicKey
	Priv *PrivateKey
}

// CSMessage represents a Cramer-Shoup message.
type CSMessage struct {
	U1, U2, E, V curve.Point
}

func (cs *CramerShoup) derivePrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.X1, err1 = cs.Curve.RandLongTermScalar(rand)
	priv.X2, err2 = cs.Curve.RandLongTermScalar(rand)
	priv.Y1, err3 = cs.Curve.RandLongTermScalar(rand)
	priv.Y2, err4 = cs.Curve.RandLongTermScalar(rand)
	priv.Z, err5 = cs.Curve.RandLongTermScalar(rand)

	return priv, utils.FirstError(err1, err2, err3, err4, err5)
}

// GenerateKeys generates a key pair of Cramer-Shoup keys.
func (cs *CramerShoup) GenerateKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.Priv, err = cs.derivePrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.Pub = &PublicKey{}
	keyPair.Pub.C = cs.Curve.PointDoubleScalarMul(cs.Curve.G(), keyPair.Priv.X1, utils.G2, keyPair.Priv.X2)
	keyPair.Pub.D = cs.Curve.PointDoubleScalarMul(cs.Curve.G(), keyPair.Priv.Y1, utils.G2, keyPair.Priv.Y2)
	keyPair.Pub.H = cs.Curve.PointScalarMul(cs.Curve.G(), keyPair.Priv.Z)

	return keyPair, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// four points. Errors can result from reading random.
func (cs *CramerShoup) Encrypt(message []byte, rand io.Reader, pub *PublicKey) (*CSMessage, error) {
	csm := &CSMessage{}

	// XXX: why not use RandLongTermScalar?
	r, err := utils.RandScalar(rand)
	if err != nil {
		return nil, err
	}

	// u = G1*r, u2 = G2*r
	csm.U1 = cs.Curve.PointScalarMul(cs.Curve.G(), r)
	csm.U2 = cs.Curve.PointScalarMul(utils.G2, r)

	// e = (h*r) + m
	csm.E = cs.Curve.AddPoints(cs.Curve.PointScalarMul(pub.H, r), cs.Curve.DecodePoint(message))

	// α = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.U1, csm.U2, csm.E)

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a := cs.Curve.PointScalarMul(pub.C, r)
	b := cs.Curve.PointScalarMul(cs.Curve.PointScalarMul(pub.D, r), alpha)
	csm.V = cs.Curve.AddPoints(a, b)

	return csm, nil
}

// Decrypt takes four points, resulting from an Cramer-Shoup encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid.
// XXX: check if message is zero
func (cs *CramerShoup) Decrypt(priv *PrivateKey, csm *CSMessage) (message []byte, err error) {
	// alpha = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.U1, csm.U2, csm.E)

	// (u1*(x1+y1*alpha) +u2*(x2+ y2*alpha) == v
	// a = (u1*x1)+(u2*x2)
	a := cs.Curve.PointDoubleScalarMul(csm.U1, priv.X1, csm.U2, priv.X2)

	// b = (u1*y1)+(u2*y2)
	b := cs.Curve.PointDoubleScalarMul(csm.U1, priv.Y1, csm.U2, priv.Y2)
	v0 := cs.Curve.PointScalarMul(b, alpha)
	v0 = cs.Curve.AddPoints(a, v0)

	ok := cs.Curve.EqualPoints(v0, csm.V)
	if !ok {
		return nil, errors.New("cannot decrypt the message")
	}

	// m = e - u1*z
	m := cs.Curve.PointScalarMul(csm.U1, priv.Z)
	m = cs.Curve.SubPoints(csm.E, m)
	message = m.Encode()

	return
}
