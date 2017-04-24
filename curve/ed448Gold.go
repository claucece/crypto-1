package curve

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

type ed448GoldPoint struct {
	p ed448.Point
}

// Encode implements point encoding for Ed448-Goldilocks
func (gp ed448GoldPoint) Encode() []byte {
	return gp.p.Encode()
}

func wrapPoint(in ed448.Point) Point {
	return ed448GoldPoint{in}
}

func unwrapPoint(in Point) ed448.Point {
	return in.(ed448GoldPoint).p
}

const (
	// TODO should get from ed448 lib
	scalarSize = 56
)

type ed448GoldScalar struct {
	s ed448.Scalar
}

// Encode implements scalar encoding for Ed448-Goldilocks
func (gs ed448GoldScalar) Encode() []byte {
	return gs.s.Encode()
}

func wrapScalar(in ed448.Scalar) Scalar {
	return ed448GoldScalar{in}
}

func unwrapScalar(in Scalar) ed448.Scalar {
	return in.(ed448GoldScalar).s
}

// Ed448Gold is the implementation of Ed448-Goldilocks
type Ed448Gold struct{}

// Ed448GoldScalar returns a new Ed448-Goldilocks scalar
func Ed448GoldScalar(bs []byte) Scalar {
	return wrapScalar(ed448.NewScalar(bs))
}

// Ed448GoldPoint returns a new Ed448-Goldilocks point from 4 arrays of 16 uint32s
func Ed448GoldPoint(a [16]uint32, b [16]uint32, c [16]uint32, d [16]uint32) Point {
	return wrapPoint(ed448.NewPoint(a, b, c, d))
}

// G returns the Ed448-Goldilocks base point
func (c *Ed448Gold) G() Point {
	return wrapPoint(ed448.BasePoint)
}

// G2 returns a second generator for Ed448-Goldilocks
func (c *Ed448Gold) G2() Point {
	return Ed448GoldPoint(
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
}

// Q returns the Ed448-Goldilocks prime order
func (c *Ed448Gold) Q() Scalar {
	return wrapScalar(ed448.ScalarQ)
}

// PrecompScalarMul multiplies a given scalar by the curve's base point
func (c *Ed448Gold) PrecompScalarMul(s Scalar) Point {
	return wrapPoint(ed448.PrecomputedScalarMul(unwrapScalar(s)))
}

// PointScalarMul multiplies a given point by a given scalar
func (c *Ed448Gold) PointScalarMul(p Point, s Scalar) Point {
	return wrapPoint(ed448.PointScalarMul(unwrapPoint(p), unwrapScalar(s)))
}

// AddPoints performs point addition
func (c *Ed448Gold) AddPoints(p1 Point, p2 Point) Point {
	p := ed448.NewPointFromBytes()
	p.Add(unwrapPoint(p1), unwrapPoint(p2))
	return wrapPoint(p)
}

// SubPoints performs point subtraction in the form of p1 - p2
func (c *Ed448Gold) SubPoints(p1 Point, p2 Point) Point {
	p := ed448.NewPointFromBytes()
	p.Sub(unwrapPoint(p1), unwrapPoint(p2))
	return wrapPoint(p)
}

// RandLongTermScalar derives a scalar from hashing the bytes retrieved from a reader
func (c *Ed448Gold) RandLongTermScalar(r io.Reader) (Scalar, error) {
	var b [scalarSize]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}
	hash := sha3.NewShake256()
	hash.Write(b[:])
	// TODO: should this really be hardcoded here?
	// TODO: this exact string is required for the tests to pass. should we use the cramershoup_secret string for the elgamal system?
	hash.Write([]byte("cramershoup_secret"))
	var out [scalarSize]byte
	hash.Read(out[:])
	return wrapScalar(ed448.NewScalar(out[:])), nil
}

// RandScalar derives a random scalar without hashing the bytes retrieved from the reader
func (c *Ed448Gold) RandScalar(r io.Reader) (Scalar, error) {
	var b [scalarSize]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}
	return Ed448GoldScalar(b[:]), nil
}

// DecodePoint implements Point decoding for Ed448-Goldilocks
func (c *Ed448Gold) DecodePoint(bs []byte) Point {
	p := ed448.NewPointFromBytes()
	p.Decode(bs, false)
	return wrapPoint(p)
}

// PointDoubleScalarMul implements double point scalar multiplication
// resulting in p1 * s1 + p2 * s2
func (c *Ed448Gold) PointDoubleScalarMul(p1 Point, s1 Scalar, p2 Point, s2 Scalar) Point {
	return wrapPoint(ed448.PointDoubleScalarMul(unwrapPoint(p1), unwrapPoint(p2), unwrapScalar(s1), unwrapScalar(s2)))
}

// EqualPoints returns whether two given points are equal
func (c *Ed448Gold) EqualPoints(p1 Point, p2 Point) bool {
	return unwrapPoint(p1).Equals(unwrapPoint(p2))
}

// IsOnCurve will return whether a point is on the Ed448-Goldilocks curve
func (c *Ed448Gold) IsOnCurve(p Point) bool {
	return unwrapPoint(p).IsOnCurve()
}

// Mul multiplies two scalars
func (c *Ed448Gold) Mul(s1 Scalar, s2 Scalar) Scalar {
	s := ed448.NewScalar()
	s.Mul(unwrapScalar(s1), unwrapScalar(s2))
	return wrapScalar(s)
}

// SubScalars subtracts two scalars
func (c *Ed448Gold) SubScalars(s1 Scalar, s2 Scalar) Scalar {
	s := ed448.NewScalar()
	s.Sub(unwrapScalar(s1), unwrapScalar(s2))
	return wrapScalar(s)
}

// EqualScalars compares two scalar values for equality
func (c *Ed448Gold) EqualScalars(s1 Scalar, s2 Scalar) bool {
	return unwrapScalar(s1).Equals(unwrapScalar(s2))
}

// HashToScalar will append and hash bytes, points, and scalars into a scalar
func (c *Ed448Gold) HashToScalar(items ...interface{}) Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, Append(items...))
	return Ed448GoldScalar(hash)
}
