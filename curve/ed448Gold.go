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

// Ed448GoldPointFromBytes returns a new Ed448-Goldilocks point from a slice of bytes
func Ed448GoldPointFromBytes(bs []byte) Point {
	return wrapPoint(ed448.NewPointFromBytes(bs))
}

// G returns the Ed448-Goldilocks base point
func (c *Ed448Gold) G() Point {
	return wrapPoint(ed448.BasePoint)
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

// RandLongTermScalar derives a scalar from the bytes retrieved from a reader
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
