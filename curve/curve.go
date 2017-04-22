package curve

import "io"

// Curve is the interface required for interacting with the included cryptosystems
type Curve interface {
	G() Point
	Q() Scalar
	PrecompScalarMul(Scalar) Point
	PointScalarMul(Point, Scalar) Point
	Add(Point, Point) Point
	Sub(Point, Point) Point
	RandLongTermScalar(io.Reader) (Scalar, error)
	DecodePoint([]byte) Point
}

// Point is the point interface required for interacting with the included cryptosystems
type Point interface {
	Encode() []byte
}

// Scalar is the scalar interface required for interacting with the included cryptosystems
type Scalar interface{}
