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
	curve.SecondGenerator
	curve.PointDoubleScalarMultiplier
	curve.PointCalculator
	curve.PointComparer
	curve.Decoder
}

// PublicKey represents a Cramer-Shoup public key.
type PublicKey struct {
	C, D, H curve.Point
}

// SecretKey represents a Cramer-Shoup private key.
type SecretKey struct {
	X1, X2, Y1, Y2, Z curve.Scalar
}

// KeyPair represents a Cramer-Shoup key pair.
type KeyPair struct {
	Pub *PublicKey
	Sec *SecretKey
}

// CSMessage represents a Cramer-Shoup message.
type CSMessage struct {
	U1, U2, E, V curve.Point
}

func (cs *CramerShoup) deriveSecretKey(rand io.Reader) (*SecretKey, error) {
	sec := &SecretKey{}
	var err1, err2, err3, err4, err5 error

	sec.X1, err1 = cs.Curve.RandLongTermScalar(rand)
	sec.X2, err2 = cs.Curve.RandLongTermScalar(rand)
	sec.Y1, err3 = cs.Curve.RandLongTermScalar(rand)
	sec.Y2, err4 = cs.Curve.RandLongTermScalar(rand)
	sec.Z, err5 = cs.Curve.RandLongTermScalar(rand)

	return sec, utils.FirstError(err1, err2, err3, err4, err5)
}

// GenerateKeys generates a key pair of Cramer-Shoup keys.
func (cs *CramerShoup) GenerateKeys(rand io.Reader) (*KeyPair, error) {
	sec, err := cs.deriveSecretKey(rand)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Sec: sec,
		Pub: &PublicKey{
			C: cs.Curve.PointDoubleScalarMul(cs.Curve.G(), sec.X1, cs.Curve.G2(), sec.X2),
			D: cs.Curve.PointDoubleScalarMul(cs.Curve.G(), sec.Y1, cs.Curve.G2(), sec.Y2),
			H: cs.Curve.PointScalarMul(cs.Curve.G(), sec.Z),
		},
	}, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// four points. Errors can result from reading random.
func (cs *CramerShoup) Encrypt(message []byte, rand io.Reader, pub *PublicKey) (*CSMessage, error) {
	// XXX: why not use RandLongTermScalar?
	r, err := utils.RandScalar(rand)
	if err != nil {
		return nil, err
	}

	// u1 = G1*r, u2 = G2*r
	u1 := cs.Curve.PointScalarMul(cs.Curve.G(), r)
	u2 := cs.Curve.PointScalarMul(cs.Curve.G2(), r)

	// e = (h*r) + m
	e := cs.Curve.AddPoints(cs.Curve.PointScalarMul(pub.H, r), cs.Curve.DecodePoint(message))

	// a = c * r
	// alpha = H(u1,u2,e)
	// b = d*(r * alpha)
	// v = a + b
	a := cs.Curve.PointScalarMul(pub.C, r)
	alpha := utils.AppendAndHash(u1, u2, e)
	b := cs.Curve.PointScalarMul(cs.Curve.PointScalarMul(pub.D, r), alpha)
	v := cs.Curve.AddPoints(a, b)

	return &CSMessage{
		U1: u1,
		U2: u2,
		E:  e,
		V:  v,
	}, nil
}

// Decrypt takes four points, resulting from an Cramer-Shoup encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid.
// XXX: check if message is zero
func (cs *CramerShoup) Decrypt(sec *SecretKey, csm *CSMessage) ([]byte, error) {
	// a = (u1*x1)+(u2*x2)
	a := cs.Curve.PointDoubleScalarMul(csm.U1, sec.X1, csm.U2, sec.X2)

	// b = (u1*y1)+(u2*y2)
	b := cs.Curve.PointDoubleScalarMul(csm.U1, sec.Y1, csm.U2, sec.Y2)

	// alpha = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.U1, csm.U2, csm.E)

	// v = u1*(x1+y1*alpha) + u2*(x2+ y2*alpha)
	v := cs.Curve.AddPoints(a, cs.Curve.PointScalarMul(b, alpha))

	// v == csm.v
	if !cs.Curve.EqualPoints(v, csm.V) {
		return nil, errors.New("cannot decrypt the message")
	}

	// m = e - u1*z
	m := cs.Curve.SubPoints(csm.E, cs.Curve.PointScalarMul(csm.U1, sec.Z))
	return m.Encode(), nil
}
