package utils

import "io"

type fixedRandReader struct {
	data []byte
	at   int
}

// FixedRand return data that looks random
func FixedRand(data []byte) io.Reader {
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
