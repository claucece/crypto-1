package data

import (
	"errors"
	"io"

	"github.com/twstrike/ed448"
	"golang.org/x/crypto/sha3"
)

// RandScalar bla
func RandScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	return ed448.NewScalar(b[:]), nil
}

// RandLongTermScalar bla
func RandLongTermScalar(rand io.Reader) (ed448.Scalar, error) {
	var b [fieldBytes]byte
	var out [fieldBytes]byte

	_, err := io.ReadFull(rand, b[:])
	if err != nil {
		return nil, errors.New("cannot source enough entropy")
	}

	hash := sha3.NewShake256()
	hash.Write(b[:])
	hash.Write([]byte("cramershoup_secret"))
	hash.Read(out[:])

	return ed448.NewScalar(out[:]), nil
}
