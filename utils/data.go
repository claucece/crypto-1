package utils

import (
	"github.com/twtiger/crypto/curve"
	"golang.org/x/crypto/sha3"
)

func shakeToScalar(in []byte) curve.Scalar {
	hash := make([]byte, 56)
	sha3.ShakeSum256(hash, in)
	s := curve.Ed448GoldScalar(hash)
	return s
}

// AppendBytes appends bytes
func AppendBytes(bs ...interface{}) []byte {
	var b []byte

	if len(bs) < 2 {
		panic("programmer error: missing append arguments")
	}

	for _, e := range bs {
		switch i := e.(type) {
		case curve.Point:
			b = append(b, i.Encode()...)
		case curve.Scalar:
			b = append(b, i.Encode()...)
		case []byte:
			b = append(b, i...)
		default:
			panic("programmer error: invalid input")
		}
	}
	return b
}

// AppendAndHash appends and hash bytes arrays
func AppendAndHash(bs ...interface{}) curve.Scalar {
	return shakeToScalar(AppendBytes(bs...))
}
