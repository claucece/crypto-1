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

// Encode implements Point encoding for Ed448-Goldilocks
func (gp ed448GoldPoint) Encode() []byte {
	return gp.p.Encode()
}

func wrapPoint(in ed448.Point) Point {
	return ed448GoldPoint{in}
}

func unwrapPoint(in Point) ed448.Point {
	return in.(ed448GoldPoint).p
}

type ed448GoldScalar struct {
	s ed448.Scalar
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

// Add performs point addition
func (c *Ed448Gold) Add(p1 Point, p2 Point) Point {
	p := ed448.NewPointFromBytes()
	p.Add(unwrapPoint(p1), unwrapPoint(p2))
	return wrapPoint(p)
}

// Sub performs point subtraction in the form of p1 - p2
func (c *Ed448Gold) Sub(p1 Point, p2 Point) Point {
	p := ed448.NewPointFromBytes()
	p.Sub(unwrapPoint(p1), unwrapPoint(p2))
	return wrapPoint(p)
}

const (
	// TODO should get from ed448 lib
	scalarSize = 56
)

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
