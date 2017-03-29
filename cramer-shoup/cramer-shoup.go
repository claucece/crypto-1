package cramershoup

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
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

var (
	g2 = ed448.NewPoint(
		[16]uint32{
			0x0cf14237, 0x0ac97f43, 0x0a9543bc, 0x0dc98db8,
			0x0bcca6a6, 0x07874a17, 0x021af78f, 0x0fffa763,
			0x0cf2ac0b, 0x074f2a89, 0x0f89f88d, 0x0356a31e,
			0x09f61e5a, 0x00c01083, 0x0c84b7a5, 0x00bf3b5c,
		},
		[16]uint32{
			0x00c9a64c, 0x06b775bc, 0x026148bb, 0x0ee0c3e1,
			0x0303aa98, 0x04fad09b, 0x0efaf59d, 0x03008555,
			0x072a0bf6, 0x023bc0fa, 0x0c52ee5b, 0x0f0f61f9,
			0x05cf8d7f, 0x0b8b7f38, 0x018a4398, 0x06a9849a,
		},
		[16]uint32{
			0x014e2fce, 0x0198c24c, 0x0b74b290, 0x0080f748,
			0x0fb60b6e, 0x08ab2f53, 0x06c32b60, 0x06979188,
			0x0e87a66d, 0x087ecac7, 0x0f354ebd, 0x035faebf,
			0x0e30d07f, 0x0c96f513, 0x0fab82ed, 0x0da28e58,
		},
		[16]uint32{
			0x0702239a, 0x05c67537, 0x0ce76a54, 0x0fae388e,
			0x034bcae9, 0x06b5fe3d, 0x0d3c37ae, 0x09cac77d,
			0x0761a657, 0x0a02246f, 0x06490757, 0x09448b04,
			0x05281bbe, 0x0e0bd3d4, 0x0abc5ecb, 0x07c655f9,
		},
	)
)

func appendPoint(b []byte, p ed448.Point) []byte {
	return append(b, p.Encode()...)
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func extractPoint(b []byte, cursor int) (ed448.Point, int, error) {
	if len(b) < 56 {
		return nil, 0, errors.New("invalid length")
	}

	p := ed448.NewPointFromBytes()
	valid, err := p.Decode(b[cursor:cursor+56], false)
	if !valid {
		return nil, 0, err
	}

	cursor += 56

	return p, cursor, err
}

func shakeToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewScalar(hash)
	return s
}

func appendAndHash(bs ...interface{}) ed448.Scalar {
	return shakeToScalar(appendBytes(bs...))
}

func appendBytes(bs ...interface{}) []byte {
	var b []byte

	if len(bs) < 2 {
		panic("programmer error: missing append arguments")
	}

	for _, e := range bs {
		switch i := e.(type) {
		case ed448.Point:
			b = append(b, i.Encode()...)
		case ed448.Scalar:
			b = append(b, i.Encode()...)
		case []byte:
			b = append(b, i...)
		default:
			panic("programmer error: invalid input")
		}
	}
	return b
}

func randScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [56]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	return ed448.NewScalar(b[:]), nil
}

func randLongTermScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [56]byte
	var out [56]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	hash := sha3.NewShake256()
	hash.Write(b[:])
	hash.Write([]byte("cramershoup_secret"))
	hash.Read(out[:])

	return ed448.NewScalar(out[:]), nil
}

//XXX: make random part of something else: conversation?
func deriveCramerShoupPrivKey(rand io.Reader) (*cramerShoupPrivateKey, error) {
	priv := &cramerShoupPrivateKey{}
	var err1, err2, err3, err4, err5 error

	priv.x1, err1 = randLongTermScalar(rand)
	priv.x2, err2 = randLongTermScalar(rand)
	priv.y1, err3 = randLongTermScalar(rand)
	priv.y2, err4 = randLongTermScalar(rand)
	priv.z, err5 = randLongTermScalar(rand)

	return priv, firstError(err1, err2, err3, err4, err5)
}

func deriveCramerShoupKeys(rand io.Reader) (*cramerShoupKeyPair, error) {
	var err error
	keyPair := &cramerShoupKeyPair{}

	keyPair.priv, err = deriveCramerShoupPrivKey(rand)
	if err != nil {
		return nil, err
	}

	keyPair.pub = &cramerShoupPublicKey{}
	keyPair.pub.c = ed448.PointDoubleScalarMul(ed448.BasePoint, g2, keyPair.priv.x1, keyPair.priv.x2)
	keyPair.pub.d = ed448.PointDoubleScalarMul(ed448.BasePoint, g2, keyPair.priv.y1, keyPair.priv.y2)
	keyPair.pub.h = ed448.PointScalarMul(ed448.BasePoint, keyPair.priv.z)

	return keyPair, nil
}

func (csm *cramerShoupMessage) cramerShoupEnc(message []byte, rand io.Reader, pub *cramerShoupPublicKey) error {
	r, err := randScalar(rand)
	if err != nil {
		return err
	}

	// u = G1*r, u2 = G2*r
	csm.u1 = ed448.PointScalarMul(ed448.BasePoint, r)
	csm.u2 = ed448.PointScalarMul(g2, r)

	// e = (h*r) + m
	m := ed448.NewPointFromBytes()
	m.Decode(message, false)
	csm.e = ed448.PointScalarMul(pub.h, r)
	csm.e.Add(csm.e, m)

	// α = H(u1,u2,e)
	alpha := appendAndHash(csm.u1, csm.u2, csm.e)

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
	alpha := appendAndHash(csm.u1, csm.u2, csm.e)

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
	rslt = appendPoint(rslt, pub.c)
	rslt = appendPoint(rslt, pub.d)
	rslt = appendPoint(rslt, pub.h)
	return rslt
}

func deserialize(ser []byte) (*cramerShoupPublicKey, error) {
	if len(ser) < 58 {
		return nil, errors.New("invalid length")
	}

	var err1, err2, err3 error
	cursor := 2

	c, cursor, err1 := extractPoint(ser, cursor)
	d, cursor, err2 := extractPoint(ser, cursor)
	h, cursor, err3 := extractPoint(ser, cursor)

	pub := &cramerShoupPublicKey{c, d, h}

	return pub, firstError(err1, err2, err3)
}
