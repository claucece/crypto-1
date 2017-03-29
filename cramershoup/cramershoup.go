package cramershoup

import (
	"errors"
	"io"

	"github.com/twstrike/ed448"
	// XXX: find a way to do this
	. "github.com/twtiger/crypto/data"
)

// XXX: serialize as MPI
type cramerShoupPrivateKey struct {
	x1, x2, y1, y2, z ed448.Scalar
}

type cramerShoupPublicKey struct {
	c, d, h ed448.Point
}

type cramerShoupKeyPair struct {
	pub  *cramerShoupPublicKey
	priv *cramerShoupPrivateKey
}

type cramerShoupMessage struct {
	u1, u2, e, v ed448.Point
}

func deriveCramerShoupPrivKey(rand io.Reader) (*cramerShoupPrivateKey, error) {
	priv := &cramerShoupPrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.x1, err1 = RandLongTermScalar(rand)
	priv.x2, err2 = RandLongTermScalar(rand)
	priv.y1, err3 = RandLongTermScalar(rand)
	priv.y2, err4 = RandLongTermScalar(rand)
	priv.z, err5 = RandLongTermScalar(rand)

	return priv, FirstError(err1, err2, err3, err4, err5)
}

func deriveCramerShoupKeys(rand io.Reader) (*cramerShoupKeyPair, error) {
	var err error
	keyPair := &cramerShoupKeyPair{}

	keyPair.priv, err = deriveCramerShoupPrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.pub = &cramerShoupPublicKey{}
	keyPair.pub.c = ed448.PointDoubleScalarMul(ed448.BasePoint, G2, keyPair.priv.x1, keyPair.priv.x2)
	keyPair.pub.d = ed448.PointDoubleScalarMul(ed448.BasePoint, G2, keyPair.priv.y1, keyPair.priv.y2)
	keyPair.pub.h = ed448.PointScalarMul(ed448.BasePoint, keyPair.priv.z)

	return keyPair, nil
}

func (csm *cramerShoupMessage) cramerShoupEnc(message []byte, rand io.Reader, pub *cramerShoupPublicKey) error {
	r, err := RandScalar(rand)
	if err != nil {
		return err
	}

	// u = G1*r, u2 = G2*r
	csm.u1 = ed448.PointScalarMul(ed448.BasePoint, r)
	csm.u2 = ed448.PointScalarMul(G2, r)

	// e = (h*r) + m
	m := ed448.NewPointFromBytes()
	m.Decode(message, false)
	csm.e = ed448.PointScalarMul(pub.h, r)
	csm.e.Add(csm.e, m)

	// α = H(u1,u2,e)
	alpha := AppendAndHash(csm.u1, csm.u2, csm.e)

	// a = c * r
	// b = d*(r * alpha)
	// v = s + t
	a := ed448.PointScalarMul(pub.c, r)
	b := ed448.PointScalarMul(pub.d, r)
	b = ed448.PointScalarMul(b, alpha)
	csm.v = ed448.NewPointFromBytes()
	csm.v.Add(a, b)
	return nil
}

func (csm *cramerShoupMessage) cramerShoupDec(priv *cramerShoupPrivateKey) (message []byte, err error) {
	// alpha = H(u1,u2,e)
	alpha := AppendAndHash(csm.u1, csm.u2, csm.e)

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

func (pub *cramerShoupPublicKey) serialize() []byte {
	if pub.c == nil || pub.d == nil || pub.h == nil {
		return nil
	}

	// XXX: do a serialize int instead?
	rslt := csPubKeyType
	rslt = AppendPoint(rslt, pub.c)
	rslt = AppendPoint(rslt, pub.d)
	rslt = AppendPoint(rslt, pub.h)
	return rslt
}

func deserialize(ser []byte) (*cramerShoupPublicKey, error) {
	if len(ser) < 58 {
		return nil, errors.New("invalid length")
	}

	var err1, err2, err3 error
	cursor := 2

	c, cursor, err1 := ExtractPoint(ser, cursor)
	d, cursor, err2 := ExtractPoint(ser, cursor)
	h, cursor, err3 := ExtractPoint(ser, cursor)

	pub := &cramerShoupPublicKey{c, d, h}

	return pub, FirstError(err1, err2, err3)
}
