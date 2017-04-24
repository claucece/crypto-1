package testHelpers

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/twtiger/crypto/curve"
)

const (
	// TODO: should get this from the ed448 package
	scalarSize = 56
)

type fixedRandReader struct {
	data []byte
	at   int
}

// FixedRandReader implements an io.Reader that will return bytes from the "data"
// parameter when Read is called
func FixedRandReader(data []byte) io.Reader {
	return &fixedRandReader{data, 0}
}

func (r *fixedRandReader) Read(p []byte) (n int, err error) {
	if r.at < len(r.data) {
		n = copy(p, r.data[r.at:])
		// TODO: is this a bug or not?
		r.at += 56
		return
	}
	return 0, io.ErrUnexpectedEOF
}

// MustCreateRandScalar returns a random scalar and panics if it cannot create one
// This was only created for testing purposes
func MustCreateRandScalar() curve.Scalar {
	var b [scalarSize]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic("cannot source enough entropy to create a random scalar")
	}
	var out [scalarSize]byte
	hash := sha3.NewShake256()
	hash.Write(b[:])
	hash.Read(out[:])
	return curve.Ed448GoldScalar(b[:])

}
