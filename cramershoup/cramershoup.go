package cramershoup

import (
	"errors"
	"io"

	"github.com/twstrike/ed448"
	"github.com/twtiger/crypto/utils"
)

// PublicKey represents a Cramer-Shoup public key.
type PublicKey struct {
	c, d, h ed448.Point
}

// PrivateKey represents a Cramer-Shoup private key.
type PrivateKey struct {
	x1, x2, y1, y2, z ed448.Scalar
}

// KeyPair represents a Cramer-Shoup key pair.
type KeyPair struct {
	pub  *PublicKey
	priv *PrivateKey
}

// CSMessage represents a Cramer-Shoup message.
type CSMessage struct {
	u1, u2, e, v ed448.Point
}

func derivePrivKey(rand io.Reader) (*PrivateKey, error) {
	priv := &PrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.x1, err1 = utils.RandLongTermScalar(rand)
	priv.x2, err2 = utils.RandLongTermScalar(rand)
	priv.y1, err3 = utils.RandLongTermScalar(rand)
	priv.y2, err4 = utils.RandLongTermScalar(rand)
	priv.z, err5 = utils.RandLongTermScalar(rand)

	return priv, utils.FirstError(err1, err2, err3, err4, err5)
}

// GenerateKeys generates a key pair of Cramer-Shoup keys.
func GenerateKeys(rand io.Reader) (*KeyPair, error) {
	var err error
	keyPair := &KeyPair{}

	keyPair.priv, err = derivePrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.pub = &PublicKey{}
	keyPair.pub.c = ed448.PointDoubleScalarMul(ed448.BasePoint, utils.G2, keyPair.priv.x1, keyPair.priv.x2)
	keyPair.pub.d = ed448.PointDoubleScalarMul(ed448.BasePoint, utils.G2, keyPair.priv.y1, keyPair.priv.y2)
	keyPair.pub.h = ed448.PointScalarMul(ed448.BasePoint, keyPair.priv.z)

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
	csm.u1 = ed448.PointScalarMul(ed448.BasePoint, r)
	csm.u2 = ed448.PointScalarMul(utils.G2, r)

	// e = (h*r) + m
	msg := ed448.NewPointFromBytes()
	msg.Decode(message, false)
	csm.e = ed448.PointScalarMul(pub.h, r)
	csm.e.Add(csm.e, msg)

	// α = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.u1, csm.u2, csm.e)

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a := ed448.PointScalarMul(pub.c, r)
	b := ed448.PointScalarMul(pub.d, r)
	b = ed448.PointScalarMul(b, alpha)
	csm.v = ed448.NewPointFromBytes()
	csm.v.Add(a, b)

	return csm, nil
}

// Decrypt takes four points, resulting from an Cramer-Shoup encryption, and
// returns the plaintext of the message. An error can result only if the
// ciphertext is invalid.
func Decrypt(priv *PrivateKey, csm *CSMessage) (message []byte, err error) {
	// alpha = H(u1,u2,e)
	alpha := utils.AppendAndHash(csm.u1, csm.u2, csm.e)

	// (u1*(x1+y1*alpha) +u2*(x2+ y2*alpha) == v
	// a = (u1*x1)+(u2*x2)
	a := ed448.PointDoubleScalarMul(csm.u1, csm.u2, priv.x1, priv.x2)

	// b = (u1*y1)+(u2*y2)
	b := ed448.PointDoubleScalarMul(csm.u1, csm.u2, priv.y1, priv.y2)
	v0 := ed448.PointScalarMul(b, alpha)
	v0.Add(a, v0)
	valid := v0.Equals(csm.v)
	if !valid {
		return nil, errors.New("cannot decrypt the message")
	}

	// m = e - u1*z
	m := ed448.PointScalarMul(csm.u1, priv.z)
	m.Sub(csm.e, m)
	message = m.Encode()

	return
}

var csPubKeyType = []byte{0x00, 0x10}
var csPubKeyTypeValue = uint16(0x0010)

func (pub *PublicKey) serialize() []byte {
	if pub.c == nil || pub.d == nil || pub.h == nil {
		return nil
	}

	// XXX: do a serialize int instead?
	rslt := csPubKeyType
	rslt = utils.AppendPoint(rslt, pub.c)
	rslt = utils.AppendPoint(rslt, pub.d)
	rslt = utils.AppendPoint(rslt, pub.h)
	return rslt
}

func deserialize(ser []byte) (*PublicKey, error) {
	if len(ser) < 58 {
		return nil, errors.New("invalid length")
	}

	var err1, err2, err3 error
	cursor := 2

	c, cursor, err1 := utils.ExtractPoint(ser, cursor)
	d, cursor, err2 := utils.ExtractPoint(ser, cursor)
	h, cursor, err3 := utils.ExtractPoint(ser, cursor)

	pub := &PublicKey{c, d, h}

	return pub, utils.FirstError(err1, err2, err3)
}
