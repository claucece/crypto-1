package dre

import (
	"errors"
	"io"

	cs "github.com/twtiger/crypto/cramershoup"
	"github.com/twtiger/crypto/curve"
)

// TODO: it seems none of the functions and types in this package are exposed, so no-one could actually use them
// should we expose them if they are valuable to people?

// DRE is an instance of a Dual Receiver Encryption System
type DRE struct {
	Curve Curve
}

// Curve defines what curve functions are required for Dual Receiver Encryption
type Curve interface {
	curve.BasicCurve
	curve.SecondGenerator
	curve.PointDoubleScalarMultiplier
	curve.PointCalculator
	curve.PointComparer
	curve.PointValidator
	curve.PointDecoder
	curve.ScalarMultiplier
	curve.ScalarCalculator
	curve.ScalarComparer
	curve.Hasher
}

type drCipher struct {
	u11, u21, e1, v1, u12, u22, e2, v2 curve.Point
}

type nIZKProof struct {
	l, n1, n2 curve.Scalar
}

type drMessage struct {
	cipher drCipher
	proof  *nIZKProof
}

func (d *DRE) isValidPublicKey(pubs ...*cs.PublicKey) error {
	for _, pub := range pubs {
		// TODO: not sure if this matters, but this check is not constant time
		if !(d.Curve.IsOnCurve(pub.C) && d.Curve.IsOnCurve(pub.D) && d.Curve.IsOnCurve(pub.H)) {
			return errors.New("not a valid public key")
		}
	}
	return nil
}

func (d *DRE) genNIZKPK(rand io.Reader, m *drCipher, pub1, pub2 *cs.PublicKey, alpha1, alpha2, k1, k2 curve.Scalar) (*nIZKProof, error) {
	// TODO: why not RandLongTermScalar?
	t1, err := d.Curve.RandScalar(rand)
	if err != nil {
		return nil, err
	}
	// TODO: why not RandLongTermScalar?
	t2, err := d.Curve.RandScalar(rand)
	if err != nil {
		return nil, err
	}

	// T11 = G1 * t2
	// TODO: why not PrecompScalarMul?
	t11 := d.Curve.PointScalarMul(d.Curve.G(), t1)
	// T21 = G2 * t1
	t21 := d.Curve.PointScalarMul(d.Curve.G2(), t1)
	// T31 = (C1 + D1 * α1) * t1
	t31 := d.Curve.PointScalarMul(d.Curve.AddPoints(pub1.C, d.Curve.PointScalarMul(pub1.D, alpha1)), t1)

	// T12 = G1 * t2
	// TODO: why not PrecompScalarMul?
	t12 := d.Curve.PointScalarMul(d.Curve.G(), t2)
	// T22 = G2 * t2
	t22 := d.Curve.PointScalarMul(d.Curve.G2(), t2)
	// T32 = (C2 + D2 * α2) * t2
	t32 := d.Curve.PointScalarMul(d.Curve.AddPoints(pub2.C, d.Curve.PointScalarMul(pub2.D, alpha2)), t2)

	// T4 = H1 * t1 - H2 * t2
	a := d.Curve.PointScalarMul(pub1.H, t1)
	t4 := d.Curve.SubPoints(a, d.Curve.PointScalarMul(pub2.H, t2))

	// gV = G1 || G2 || q
	gV := curve.Append(d.Curve.G(), d.Curve.G2(), d.Curve.Q())
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := curve.Append(pub1.C, pub1.D, pub1.H, pub2.C, pub2.D, pub2.H)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := curve.Append(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := curve.Append(t11, t21, t31, t12, t22, t32, t4)

	pf := &nIZKProof{}
	pf.l = d.Curve.HashToScalar(gV, pV, eV, zV)

	// ni = ti - l * ki (mod q)
	pf.n1 = d.Curve.SubScalars(t1, d.Curve.Mul(pf.l, k1))
	pf.n2 = d.Curve.SubScalars(t2, d.Curve.Mul(pf.l, k2))
	return pf, nil
}

func (d *DRE) isValid(pf *nIZKProof, m *drCipher, pub1, pub2 *cs.PublicKey, alpha1, alpha2 curve.Scalar) (bool, error) {
	// T1j = G1 * nj + U1j * l
	t11 := d.Curve.PointDoubleScalarMul(d.Curve.G(), pf.n1, m.u11, pf.l)
	// T2j = G2 * nj + U2j * l
	t21 := d.Curve.PointDoubleScalarMul(d.Curve.G2(), pf.n1, m.u21, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t31 := d.Curve.PointDoubleScalarMul(d.Curve.AddPoints(pub1.C, d.Curve.PointScalarMul(pub1.D, alpha1)), pf.n1, m.v1, pf.l)

	// T1j = G1 * nj + U1j * l
	t12 := d.Curve.PointDoubleScalarMul(d.Curve.G(), pf.n2, m.u12, pf.l)
	// T2j = G2 * nj + U2j * l
	t22 := d.Curve.PointDoubleScalarMul(d.Curve.G2(), pf.n2, m.u22, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t32 := d.Curve.PointDoubleScalarMul(d.Curve.AddPoints(pub2.C, d.Curve.PointScalarMul(pub2.D, alpha2)), pf.n2, m.v2, pf.l)

	// T4 = H1 * n1 - H2 * n2 + (E1-E2) * l
	// a = H1 * n1
	// b = H2 * n2 - a
	a := d.Curve.PointScalarMul(pub1.H, pf.n1)
	b := d.Curve.SubPoints(a, d.Curve.PointScalarMul(pub2.H, pf.n2))
	c := d.Curve.SubPoints(m.e1, m.e2)
	t4 := d.Curve.AddPoints(b, d.Curve.PointScalarMul(c, pf.l))

	// gV = G1 || G2 || q
	gV := curve.Append(d.Curve.G(), d.Curve.G2(), d.Curve.Q())
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := curve.Append(pub1.C, pub1.D, pub1.H, pub2.C, pub2.D, pub2.H)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := curve.Append(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := curve.Append(t11, t21, t31, t12, t22, t32, t4)

	// l' = HashToScalar(gV || pV || eV || zV)
	ll := d.Curve.HashToScalar(gV, pV, eV, zV)

	if d.Curve.EqualScalars(pf.l, ll) {
		return true, nil
	}
	return false, errors.New("cannot decrypt the message")
}

func (d *DRE) verifyDRMessage(u1, u2, v curve.Point, alpha curve.Scalar, sec *cs.SecretKey) (bool, error) {
	// U1i * x1i + U2i * x2i + (U1i * y1i + U2i * y2i) * αi ≟ Vi
	// a = (u11*x1)+(u21*x2)
	a := d.Curve.PointDoubleScalarMul(u1, sec.X1, u2, sec.X2)
	// b = (u11*y1)+(u21*y2)
	b := d.Curve.PointDoubleScalarMul(u1, sec.Y1, u2, sec.Y2)
	c := d.Curve.AddPoints(a, d.Curve.PointScalarMul(b, alpha))
	if d.Curve.EqualPoints(c, v) {
		//XXX: is this the correct err?
		return true, nil
	}
	return false, errors.New("cannot decrypt the message")
}

func (d *DRE) drEnc(message []byte, rand io.Reader, pub1, pub2 *cs.PublicKey) (*drMessage, error) {
	err := d.isValidPublicKey(pub1, pub2)
	if err != nil {
		return nil, err
	}

	k1, err := d.Curve.RandScalar(rand)
	if err != nil {
		return nil, err
	}
	k2, err := d.Curve.RandScalar(rand)
	if err != nil {
		return nil, err
	}

	gamma := &drMessage{}
	// u1i = G1*ki, u2i = G2*ki
	gamma.cipher.u11 = d.Curve.PointScalarMul(d.Curve.G(), k1)
	gamma.cipher.u21 = d.Curve.PointScalarMul(d.Curve.G2(), k1)
	gamma.cipher.u12 = d.Curve.PointScalarMul(d.Curve.G(), k2)
	gamma.cipher.u22 = d.Curve.PointScalarMul(d.Curve.G2(), k2)

	// ei = (hi*ki) + m
	m := d.Curve.DecodePoint(message)
	gamma.cipher.e1 = d.Curve.AddPoints(d.Curve.PointScalarMul(pub1.H, k1), m)
	gamma.cipher.e2 = d.Curve.AddPoints(d.Curve.PointScalarMul(pub2.H, k2), m)

	// αi = H(u1i,u2i,ei)
	alpha1 := d.Curve.HashToScalar(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := d.Curve.HashToScalar(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	// ai = ci * ki
	// bi = di*(ki * αi)
	// vi = ai + bi
	a1 := d.Curve.PointScalarMul(pub1.C, k1)
	b1 := d.Curve.PointScalarMul(pub1.D, k1)
	gamma.cipher.v1 = d.Curve.AddPoints(a1, d.Curve.PointScalarMul(b1, alpha1))
	a2 := d.Curve.PointScalarMul(pub2.C, k2)
	b2 := d.Curve.PointScalarMul(pub2.D, k2)
	gamma.cipher.v2 = d.Curve.AddPoints(a2, d.Curve.PointScalarMul(b2, alpha2))

	proof, err := d.genNIZKPK(rand, &gamma.cipher, pub1, pub2, alpha1, alpha2, k1, k2)
	if err != nil {
		return nil, err
	}
	gamma.proof = proof

	return gamma, nil
}

func (d *DRE) drDec(gamma *drMessage, pub1, pub2 *cs.PublicKey, sec *cs.SecretKey, index int) (message []byte, err error) {
	err = d.isValidPublicKey(pub1, pub2)
	if err != nil {
		return nil, err
	}

	// αj = HashToScalar(U1j || U2j || Ej)
	alpha1 := d.Curve.HashToScalar(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := d.Curve.HashToScalar(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	valid, err := d.isValid(gamma.proof, &gamma.cipher, pub1, pub2, alpha1, alpha2)
	if !valid {
		return nil, err
	}

	var m curve.Point
	if index == 1 {
		valid, err = d.verifyDRMessage(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.v1, alpha1, sec)
		if !valid {
			return nil, err
		}
		// m = e - u11*z
		m = d.Curve.SubPoints(gamma.cipher.e1, d.Curve.PointScalarMul(gamma.cipher.u11, sec.Z))
	} else {
		valid, err = d.verifyDRMessage(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.v2, alpha2, sec)
		if !valid {
			return nil, err
		}
		// m = e - u12*z
		m = d.Curve.SubPoints(gamma.cipher.e2, d.Curve.PointScalarMul(gamma.cipher.u12, sec.Z))
	}

	message = m.Encode()
	return
}
