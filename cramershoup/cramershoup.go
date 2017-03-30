package cramershoup

import (
	"errors"
	"io"

	"github.com/twstrike/ed448"
	"github.com/twtiger/crypto/utils"
)

// PublicKey represents a Cramer-Shoup public key.
type PublicKey struct {
	C, D, H ed448.Point
}

// PrivateKey represents a Cramer-Shoup private key.
type PrivateKey struct {
	X1, X2, Y1, Y2, Z ed448.Scalar
}

// KeyPair represents a Cramer-Shoup key pair.
type KeyPair struct {
	Pub  *PublicKey
	Priv *PrivateKey
}

// CSMessage represents a Cramer-Shoup message.
type CSMessage struct {
	U1, U2, E, V ed448.Point
}

func derivePrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.X1, err1 = utils.RandLongTermScalar(rand)
	priv.X2, err2 = utils.RandLongTermScalar(rand)
	priv.Y1, err3 = utils.RandLongTermScalar(rand)
	priv.Y2, err4 = utils.RandLongTermScalar(rand)
	priv.Z, err5 = utils.RandLongTermScalar(rand)

	return priv, utils.FirstError(err1, err2, err3, err4, err5)
}

// GenerateKeys generates a key pair of Cramer-Shoup keys.
func GenerateKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.Priv, err = derivePrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.Pub = &PublicKey{}
	keyPair.Pub.C = ed448.PointDoubleScalarMul(ed448.BasePoint, utils.G2, keyPair.Priv.X1, keyPair.Priv.X2)
	keyPair.Pub.D = ed448.PointDoubleScalarMul(ed448.BasePoint, utils.G2, keyPair.Priv.Y1, keyPair.Priv.Y2)
	keyPair.Pub.H = ed448.PointScalarMul(ed448.BasePoint, keyPair.Priv.Z)

	return keyPair, nil
}

// Encrypt encrypts the given message to the given public key. The result is a
// four points. Errors can result from reading random.
func Encrypt(message []byte, rand io.Reader, pub *PublicKey) (*CSMessage, error) {
	csm := &CSMessage{}

	r, err := utils.RandScalar(rand)
	if err != nil {
		return nil, err
	}

	// u = G1*r, u2 = G2*r
	csm.U1 = ed448.PointScalarMul(ed448.BasePoint, r)
	csm.U2 = ed448.PointScalarMul(utils.G2, r)

	// e = (h*r) + m
	msg := ed448.NewPointFromBytes()
	msg.Decode(message, false)
	csm.E = ed448.PointScalarMul(pub.H, r)
	csm.E.Add(csm.E, msg)

	// α = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.U1, csm.U2, csm.E)

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a := ed448.PointScalarMul(pub.C, r)
	b := ed448.PointScalarMul(pub.D, r)
	b = ed448.PointScalarMul(b, alpha)
	csm.V = ed448.NewPointFromBytes()
	csm.V.Add(a, b)

	return csm, nil
}

// Decrypt takes four points, resulting from an Cramer-Shoup encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid.
// XXX: check if message is zero
func Decrypt(priv *PrivateKey, csm *CSMessage) (message []byte, err error) {
	// alpha = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.U1, csm.U2, csm.E)

	// (u1*(x1+y1*alpha) +u2*(x2+ y2*alpha) == v
	// a = (u1*x1)+(u2*x2)
	a := ed448.PointDoubleScalarMul(csm.U1, csm.U2, priv.X1, priv.X2)

	// b = (u1*y1)+(u2*y2)
	b := ed448.PointDoubleScalarMul(csm.U1, csm.U2, priv.Y1, priv.Y2)
	v0 := ed448.PointScalarMul(b, alpha)
	v0.Add(a, v0)

	ok := v0.Equals(csm.V)
	if !ok {
		return nil, errors.New("cannot decrypt the message")
	}

	// m = e - u1*z
	m := ed448.PointScalarMul(csm.U1, priv.Z)
	m.Sub(csm.E, m)
	message = m.Encode()

	return
}
