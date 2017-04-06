package dre

import (
	"errors"
	"io"

	"github.com/twstrike/ed448"

	cs "github.com/twtiger/crypto/cramershoup"
	"github.com/twtiger/crypto/utils"
)

type drCipher struct {
	u11, u21, e1, v1, u12, u22, e2, v2 ed448.Point
}

type nIZKProof struct {
	l, n1, n2 ed448.Scalar
}

type drMessage struct {
	cipher drCipher
	proof  nIZKProof
}

func isValidPublicKey(pubs ...*cs.PublicKey) error {
	for _, pub := range pubs {
		if !(pub.C.IsOnCurve() && pub.D.IsOnCurve() && pub.H.IsOnCurve()) {
			return errors.New("not a valid public key")
		}
	}
	return nil
}

func (pf *nIZKProof) genNIZKPK(rand io.Reader, m *drCipher, pub1, pub2 *cs.PublicKey, alpha1, alpha2, k1, k2 ed448.Scalar) error {
	t1, err := utils.RandScalar(rand)
	if err != nil {
		return err
	}
	t2, err := utils.RandScalar(rand)
	if err != nil {
		return err
	}

	// T11 = G1 * t2
	t11 := ed448.PointScalarMul(ed448.BasePoint, t1)
	// T21 = G2 * t1
	t21 := ed448.PointScalarMul(utils.G2, t1)
	// T31 = (C1 + D1 * α1) * t1
	t31 := ed448.PointScalarMul(pub1.D, alpha1)
	t31.Add(pub1.C, t31)
	t31 = ed448.PointScalarMul(t31, t1)

	// T12 = G1 * t2
	t12 := ed448.PointScalarMul(ed448.BasePoint, t2)
	// T22 = G2 * t2
	t22 := ed448.PointScalarMul(utils.G2, t2)
	// T32 = (C2 + D2 * α2) * t2
	t32 := ed448.PointScalarMul(pub2.D, alpha2)
	t32.Add(pub2.C, t32)
	t32 = ed448.PointScalarMul(t32, t2)

	// T4 = H1 * t1 - H2 * t2
	a := ed448.PointScalarMul(pub1.H, t1)
	t4 := ed448.PointScalarMul(pub2.H, t2)
	t4.Sub(a, t4)

	// gV = G1 || G2 || q
	gV := utils.AppendBytes(ed448.BasePoint, utils.G2, ed448.ScalarQ)
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := utils.AppendBytes(pub1.C, pub1.D, pub1.H, pub2.C, pub2.D, pub2.H)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := utils.AppendBytes(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := utils.AppendBytes(t11, t21, t31, t12, t22, t32, t4)

	pf.l = utils.AppendAndHash(gV, pV, eV, zV)

	// ni = ti - l * ki (mod q)
	pf.n1, pf.n2 = ed448.NewScalar(), ed448.NewScalar()
	pf.n1.Mul(pf.l, k1)
	pf.n1.Sub(t1, pf.n1)

	pf.n2.Mul(pf.l, k2)
	pf.n2.Sub(t2, pf.n2)

	return nil
}

func (pf *nIZKProof) isValid(m *drCipher, pub1, pub2 *cs.PublicKey, alpha1, alpha2 ed448.Scalar) (bool, error) {
	// T1j = G1 * nj + U1j * l
	t11 := ed448.PointDoubleScalarMul(ed448.BasePoint, m.u11, pf.n1, pf.l)
	// T2j = G2 * nj + U2j * l
	t21 := ed448.PointDoubleScalarMul(utils.G2, m.u21, pf.n1, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t31 := ed448.PointScalarMul(pub1.D, alpha1)
	t31.Add(pub1.C, t31)
	t31 = ed448.PointDoubleScalarMul(t31, m.v1, pf.n1, pf.l)

	// T1j = G1 * nj + U1j * l
	t12 := ed448.PointDoubleScalarMul(ed448.BasePoint, m.u12, pf.n2, pf.l)
	// T2j = G2 * nj + U2j * l
	t22 := ed448.PointDoubleScalarMul(utils.G2, m.u22, pf.n2, pf.l)
	// T3j = (Cj + Dj * αj) * nj + Vj * l
	t32 := ed448.PointScalarMul(pub2.D, alpha2)
	t32.Add(pub2.C, t32)
	t32 = ed448.PointDoubleScalarMul(t32, m.v2, pf.n2, pf.l)

	// T4 = H1 * n1 - H2 * n2 + (E1-E2) * l
	// a = H1 * n1
	// b = H2 * n2 - a
	c := ed448.NewPointFromBytes()
	a := ed448.PointScalarMul(pub1.H, pf.n1)
	b := ed448.PointScalarMul(pub2.H, pf.n2)
	b.Sub(a, b)
	c.Sub(m.e1, m.e2)
	t4 := ed448.PointScalarMul(c, pf.l)
	t4.Add(b, t4)

	// gV = G1 || G2 || q
	gV := utils.AppendBytes(ed448.BasePoint, utils.G2, ed448.ScalarQ)
	// pV = C1 || D1 || H1 || C2 || D2 || H2
	pV := utils.AppendBytes(pub1.C, pub1.D, pub1.H, pub2.C, pub2.D, pub2.H)
	// eV = U11 || U21 || E1 || V1 || α1 || U12 || U22 || E2 || V2 || α2
	eV := utils.AppendBytes(m.u11, m.u21, m.e1, m.v1, alpha1, m.u12, m.u22, m.e2, m.v2, alpha2)
	// zV = T11 || T21 || T31 || T12 || T22 || T32 || T4
	zV := utils.AppendBytes(t11, t21, t31, t12, t22, t32, t4)

	// l' = HashToScalar(gV || pV || eV || zV)
	ll := utils.AppendAndHash(gV, pV, eV, zV)

	valid := pf.l.Equals(ll)

	if !valid {
		return false, errors.New("cannot decrypt the message")
	}
	return true, nil
}

func verifyDRMessage(u1, u2, v ed448.Point, alpha ed448.Scalar, priv *cs.PrivateKey) (bool, error) {
	// U1i * x1i + U2i * x2i + (U1i * y1i + U2i * y2i) * αi ≟ Vi
	// a = (u11*x1)+(u21*x2)
	a := ed448.PointDoubleScalarMul(u1, u2, priv.X1, priv.X2)
	// b = (u11*y1)+(u21*y2)
	b := ed448.PointDoubleScalarMul(u1, u2, priv.Y1, priv.Y2)
	c := ed448.PointScalarMul(b, alpha)
	c.Add(a, c)

	valid := c.Equals(v)
	if !valid {
		//XXX: is this the correct err?
		return false, errors.New("cannot decrypt the message")
	}
	return valid, nil
}

func (gamma *drMessage) drEnc(message []byte, rand io.Reader, pub1, pub2 *cs.PublicKey) (err error) {
	err = isValidPublicKey(pub1, pub2)
	if err != nil {
		return
	}

	k1, err := utils.RandScalar(rand)
	if err != nil {
		return
	}
	k2, err := utils.RandScalar(rand)
	if err != nil {
		return
	}

	// u1i = G1*ki, u2i = G2*ki
	gamma.cipher.u11 = ed448.PointScalarMul(ed448.BasePoint, k1)
	gamma.cipher.u21 = ed448.PointScalarMul(utils.G2, k1)
	gamma.cipher.u12 = ed448.PointScalarMul(ed448.BasePoint, k2)
	gamma.cipher.u22 = ed448.PointScalarMul(utils.G2, k2)

	// ei = (hi*ki) + m
	m := ed448.NewPointFromBytes(message)
	gamma.cipher.e1 = ed448.PointScalarMul(pub1.H, k1)
	gamma.cipher.e1.Add(gamma.cipher.e1, m)
	gamma.cipher.e2 = ed448.PointScalarMul(pub2.H, k2)
	gamma.cipher.e2.Add(gamma.cipher.e2, m)

	// αi = H(u1i,u2i,ei)
	alpha1 := utils.AppendAndHash(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := utils.AppendAndHash(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	// ai = ci * ki
	// bi = di*(ki * αi)
	// vi = ai + bi
	a1 := ed448.PointScalarMul(pub1.C, k1)
	b1 := ed448.PointScalarMul(pub1.D, k1)
	gamma.cipher.v1 = ed448.PointScalarMul(b1, alpha1)
	gamma.cipher.v1.Add(a1, gamma.cipher.v1)
	a2 := ed448.PointScalarMul(pub2.C, k2)
	b2 := ed448.PointScalarMul(pub2.D, k2)
	gamma.cipher.v2 = ed448.PointScalarMul(b2, alpha2)
	gamma.cipher.v2.Add(a2, gamma.cipher.v2)

	err = gamma.proof.genNIZKPK(rand, &gamma.cipher, pub1, pub2, alpha1, alpha2, k1, k2)
	if err != nil {
		return
	}

	return nil
}

func (gamma *drMessage) drDec(pub1, pub2 *cs.PublicKey, priv *cs.PrivateKey, index int) (message []byte, err error) {
	err = isValidPublicKey(pub1, pub2)
	if err != nil {
		return nil, err
	}

	// αj = HashToScalar(U1j || U2j || Ej)
	alpha1 := utils.AppendAndHash(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.e1)
	alpha2 := utils.AppendAndHash(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.e2)

	valid, err := gamma.proof.isValid(&gamma.cipher, pub1, pub2, alpha1, alpha2)
	if !valid {
		return nil, err
	}

	var m ed448.Point
	if index == 1 {
		valid, err = verifyDRMessage(gamma.cipher.u11, gamma.cipher.u21, gamma.cipher.v1, alpha1, priv)
		if !valid {
			return nil, err
		}
		// m = e - u11*z
		m = ed448.PointScalarMul(gamma.cipher.u11, priv.Z)
		m.Sub(gamma.cipher.e1, m)
	} else {
		valid, err = verifyDRMessage(gamma.cipher.u12, gamma.cipher.u22, gamma.cipher.v2, alpha2, priv)
		if !valid {
			return nil, err
		}
		// m = e - u12*z
		m = ed448.PointScalarMul(gamma.cipher.u12, priv.Z)
		m.Sub(gamma.cipher.e2, m)
	}

	message = m.Encode()
	return
}
