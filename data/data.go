package data

import (
	"errors"

	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

// ShakeToScalar hashes a byte array into a scalar using SHAKE
func ShakeToScalar(in []byte) ed448.Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, in)
	s := ed448.NewScalar(hash)
	return s
}

// AppendAndHash appends and hash bytes arrays
func AppendAndHash(bs ...interface{}) ed448.Scalar {
	return ShakeToScalar(AppendBytes(bs...))
}

// AppendBytes appends bytes
func AppendBytes(bs ...interface{}) []byte {
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

// AppendPoint appends a point to a byte array
func AppendPoint(b []byte, p ed448.Point) []byte {
	return append(b, p.Encode()...)
}

// ExtractPoint extracts a point from a byte array
func ExtractPoint(b []byte, cursor int) (ed448.Point, int, error) {
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
