package utils

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/twstrike/ed448"
	"github.com/twtiger/crypto/curve"
	"golang.org/x/crypto/sha3"
)

// RandScalar return a random scalar
func RandScalar(rand io.Reader) (curve.Scalar, error) {
	var b [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	return curve.Ed448GoldScalar(b[:]), nil
}

// RandLongTermScalar returna a longterm scalar
func RandLongTermScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [fieldBytes]byte
	var out [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	hash := sha3.NewShake256()
	hash.Write(b[:])

	// TODO: should this really be hardcoded here?
	hash.Write([]byte("cramershoup_secret"))
	hash.Read(out[:])

	return ed448.NewScalar(out[:]), nil
}

// MustCreateRandScalar returns a random scalar and panics if it cannot create one
// This was only created for testing purposes
func MustCreateRandScalar() curve.Scalar {
	var b [fieldBytes]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic("cannot source enough entropy to create a random scalar")
	}
	var out [fieldBytes]byte
	hash := sha3.NewShake256()
	hash.Write(b[:])
	hash.Read(out[:])
	return curve.Ed448GoldScalar(b[:])

}
