package elgamal

import (
	"crypto/rand"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/twstrike/ed448"
	. "github.com/twtiger/crypto/utils"
)

func Test(t *testing.T) { TestingT(t) }

type EGSuite struct{}

var _ = Suite(&EGSuite{})

var (
	egRandData = []byte{
		// x1
		0x40, 0x80, 0x66, 0x2d, 0xd8, 0xe7, 0xf0, 0x9c,
		0xdf, 0xb0, 0x4e, 0x1c, 0x6e, 0x12, 0x62, 0xa3,
		0x7c, 0x31, 0x9a, 0xe1, 0xe7, 0x86, 0x87, 0xcc,
		0x82, 0x05, 0x78, 0xe6, 0x44, 0x2f, 0x4f, 0x77,
		0x0e, 0xd1, 0xb4, 0x48, 0xa6, 0x05, 0x90, 0x5e,
		0xe7, 0xba, 0xfc, 0x25, 0x99, 0x99, 0xb8, 0xc3,
		0x90, 0x3e, 0xf4, 0xa3, 0x75, 0xee, 0x85, 0x32,
	}
)

func (s *EGSuite) Test_DerivePrivateKey(c *C) {
	expPriv := &PrivateKey{
		// X
		ed448.NewScalar([]byte{
			0xc6, 0xd0, 0x98, 0x2e, 0xe4, 0xe5, 0x81, 0xe4,
			0x61, 0x3c, 0x46, 0x99, 0x0a, 0x37, 0x79, 0xc3,
			0xfa, 0xe5, 0xd5, 0x29, 0x27, 0x31, 0xa3, 0x55,
			0x9f, 0x34, 0x91, 0xd1, 0x0c, 0x7f, 0x88, 0x56,
			0x8c, 0x62, 0xe1, 0x86, 0xb7, 0xef, 0xd6, 0xcb,
			0x1b, 0x14, 0x88, 0x3b, 0xc0, 0xfb, 0xac, 0x46,
			0x0c, 0xc7, 0x20, 0x82, 0x3e, 0xd0, 0xdc, 0x2c,
		}),
	}

	priv, err := derivePrivKey(FixedRand(egRandData))
	c.Assert(priv, DeepEquals, expPriv)
	c.Assert(err, IsNil)

	r := make([]byte, 55)
	_, err = derivePrivKey(FixedRand(r))

	c.Assert(err, ErrorMatches, "cannot source enough entropy")
}

func (s *EGSuite) Test_EncryptionAndDecryption(c *C) {
	message := []byte{
		0xfd, 0xf1, 0x18, 0xbf, 0x8e, 0xc9, 0x64, 0xc7,
		0x94, 0x46, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xff,
		0x72, 0x5e, 0xb7, 0x61, 0x46, 0xf1, 0x93, 0xa6,
		0x70, 0x81, 0x64, 0x37, 0x7c, 0xec, 0x6c, 0xe5,
		0xc6, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x73, 0x79, 0xa6, 0x48, 0x57, 0xbb, 0x0f, 0x70,
		0x63, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	}

	keyPair, err := GenerateKeys(rand.Reader)
	c1, c2, err := Encrypt(rand.Reader, keyPair.Pub, message)

	expMessage := Decrypt(keyPair.Priv, c1, c2)

	c.Assert(expMessage, DeepEquals, message)
	c.Assert(err, IsNil)
}