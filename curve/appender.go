package curve

// Hasher is an interface for appending and hashing points, scalars, and bytes
// Implementers may determine which hash is used
type Hasher interface {
	HashToScalar(items ...interface{}) Scalar
}

// Append accepts points, scalars, and bytes and returns a slice of bytes
// Append will panic if the input contains items that are not of type point,
// scalar, or bytes
func Append(items ...interface{}) []byte {
	if len(items) < 2 {
		panic("programmer error: missing append arguments")
	}
	var b []byte
	for _, e := range items {
		switch i := e.(type) {
		case Point:
			b = append(b, i.Encode()...)
		case Scalar:
			b = append(b, i.Encode()...)
		case []byte:
			b = append(b, i...)
		default:
			panic("programmer error: invalid input")
		}
	}
	return b
}
