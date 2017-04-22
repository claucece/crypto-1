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

// SecondGenerator is an interface for retrieving a second generator on a curve
type SecondGenerator interface {
	G2() Point
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
	PointDoubleScalarMul(p1 Point, s1 Scalar, p2 Point, s2 Scalar) Point
}

// PointCalculator computes point arithmetic
type PointCalculator interface {
	AddPoints(Point, Point) Point
	SubPoints(Point, Point) Point
}

// PointComparer checks whether two points are equal
type PointComparer interface {
	EqualPoints(Point, Point) bool
}

// PointValidator will check whether a point is on the curve
type PointValidator interface {
	IsOnCurve(Point) bool
}

// Point is the point interface required for interacting with the included cryptosystems
type Point interface {
	Encode() []byte
}

// Scalar is the scalar interface required for interacting with the included cryptosystems
type Scalar interface {
	Encode() []byte
}

// ScalarMultiplier multiplies two scalars
type ScalarMultiplier interface {
	Mul(Scalar, Scalar) Scalar
}

// ScalarCalculator computes point arithmetic
type ScalarCalculator interface {
	SubScalars(Scalar, Scalar) Scalar
}

// ScalarComparer checks whether two scalars are equal
type ScalarComparer interface {
	EqualScalars(Scalar, Scalar) bool
}
