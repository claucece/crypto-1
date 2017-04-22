package curve

import "io"

// BasicCurve is the basic interface required for interacting with the included cryptosystems
type BasicCurve interface {
	// G returns the Base Point of the curve. This is exposed to allow easy access for protocols which use G directly.
	G() Point
	// Q returns the prime order of the curve. This is exposed to allow easy access for protocols which use Q directly.
	Q() Scalar
	PointScalarMul(Point, Scalar) Point
	RandLongTermScalar(io.Reader) (Scalar, error)
}

// Decoder will decode points for the curve
type Decoder interface {
	DecodePoint([]byte) Point
}

// PrecomputedMultiplier will use precomputed tables to perform point scalar multiplication
// on the base point with a given scalar
type PrecomputedMultiplier interface {
	PrecompScalarMul(Scalar) Point
}

// PointDoubleScalarMultiplier will add the results of two point scalar multiplications
// The result is p1 * s1 + p2 * s2
type PointDoubleScalarMultiplier interface {
	PointDoubleScalarMul(p1 Point, s1 Scalar, p2 Point, s2 Scalar)
}

// PointCalculator computes point arithmetic
type PointCalculator interface {
	Add(Point, Point) Point
	Sub(Point, Point) Point
}

// Point is the point interface required for interacting with the included cryptosystems
type Point interface {
	Encode() []byte
}

// Scalar is the scalar interface required for interacting with the included cryptosystems
type Scalar interface{}
