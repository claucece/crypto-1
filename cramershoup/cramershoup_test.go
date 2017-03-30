package cramershoup

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/twstrike/ed448"
	. "gopkg.in/check.v1"

	. "github.com/twtiger/crypto/utils"
)

func Test(t *testing.T) { TestingT(t) }

type CSSuite struct{}

var _ = Suite(&CSSuite{})

var (
	csRandData = []byte{
		// x1
		0x40, 0x80, 0x66, 0x2d, 0xd8, 0xe7, 0xf0, 0x9c,
		0xdf, 0xb0, 0x4e, 0x1c, 0x6e, 0x12, 0x62, 0xa3,
		0x7c, 0x31, 0x9a, 0xe1, 0xe7, 0x86, 0x87, 0xcc,
		0x82, 0x05, 0x78, 0xe6, 0x44, 0x2f, 0x4f, 0x77,
		0x0e, 0xd1, 0xb4, 0x48, 0xa6, 0x05, 0x90, 0x5e,
		0xe7, 0xba, 0xfc, 0x25, 0x99, 0x99, 0xb8, 0xc3,
		0x90, 0x3e, 0xf4, 0xa3, 0x75, 0xee, 0x85, 0x32,
		// x2
		0x16, 0xb1, 0x06, 0x5b, 0x81, 0xea, 0xac, 0xb3,
		0x69, 0x47, 0x6d, 0xa2, 0xaa, 0x86, 0x0b, 0xe5,
		0xcd, 0xac, 0x43, 0xd7, 0xb7, 0xe3, 0xb0, 0x85,
		0xd8, 0x66, 0xf9, 0xb6, 0x45, 0x2e, 0x81, 0x43,
		0xc2, 0x6f, 0x61, 0xc4, 0xdd, 0x65, 0x35, 0xa4,
		0xa4, 0xf9, 0x55, 0xf0, 0xf9, 0xd2, 0xf4, 0xb7,
		0xa4, 0xf9, 0x55, 0xf0, 0xf9, 0xd2, 0xf4, 0xb7,
		// y1
		0x52, 0x18, 0x41, 0x48, 0x60, 0x2d, 0x67, 0x8a,
		0xd3, 0xf3, 0xd2, 0xa4, 0xfd, 0x6f, 0x64, 0xf3,
		0x72, 0x82, 0xb0, 0x6a, 0x4d, 0xea, 0x9c, 0xef,
		0x99, 0x05, 0xe1, 0x8d, 0xaf, 0x2d, 0xdb, 0x52,
		0x57, 0x00, 0xac, 0x45, 0x24, 0x24, 0xb4, 0x79,
		0x02, 0x5f, 0x99, 0x70, 0x95, 0x2a, 0x90, 0x08,
		0x02, 0x5f, 0x99, 0x70, 0x95, 0x2a, 0x90, 0x08,
		// y2
		0x51, 0x5b, 0x69, 0x03, 0xd5, 0x77, 0xb0, 0x77,
		0x35, 0x1f, 0x1b, 0x2d, 0xb1, 0x26, 0xf1, 0x69,
		0x3b, 0xcc, 0x4b, 0x0a, 0x95, 0x83, 0xd7, 0xec,
		0xfa, 0x8c, 0xf7, 0x80, 0xbe, 0x9b, 0x6d, 0xb4,
		0xc3, 0x24, 0x3c, 0x94, 0x9b, 0x63, 0xbc, 0x89,
		0xbc, 0x09, 0x39, 0xb8, 0xbf, 0xa2, 0x9b, 0xf4,
		0x3a, 0xa2, 0x9b, 0xbe, 0x6e, 0x78, 0x7b, 0x11,
		// z
		0x66, 0x60, 0x01, 0xb9, 0x83, 0x10, 0xd5, 0x7d,
		0xe4, 0x86, 0x58, 0x0a, 0x42, 0xd2, 0x2a, 0x74,
		0xe9, 0x5d, 0x77, 0xc4, 0x08, 0x46, 0x31, 0xb4,
		0x75, 0x1b, 0xf2, 0x67, 0x23, 0x19, 0x5e, 0xb6,
		0xfc, 0xe8, 0xd1, 0x38, 0x81, 0xa3, 0x98, 0x41,
		0xdf, 0xdf, 0x5d, 0x8d, 0x41, 0xb4, 0x66, 0x0f,
		0x39, 0xe1, 0x6f, 0x8c, 0x89, 0xed, 0xf6, 0x11,
	}

	testPubA = &PublicKey{
		// c
		ed448.NewPoint(
			[16]uint32{
				0x0600d17a, 0x0a9375b0, 0x057841c1, 0x0d174be0,
				0x0011badb, 0x006ef801, 0x02e0a39f, 0x0fecd541,
				0x055b1c78, 0x0895cbd0, 0x072a6628, 0x0bb03485,
				0x036131cf, 0x0a79778a, 0x07e006b9, 0x097fb665,
			},
			[16]uint32{
				0x0f010a4f, 0x03e8789d, 0x047c75cc, 0x07ec8505,
				0x0225156f, 0x07e8e08f, 0x0ac4e95e, 0x065ee99b,
				0x077b97fd, 0x0c851d94, 0x07e2ef48, 0x0004fe3e,
				0x0c3e7fcb, 0x0a9dcbf1, 0x0296ae5f, 0x0b844a1f,
			},
			[16]uint32{
				0x0cb95a0b, 0x079e46f8, 0x03337dcb, 0x00dcdf8d,
				0x0629b80f, 0x0ff224ea, 0x0e697c53, 0x0a5bc379,
				0x03001fb6, 0x026826d2, 0x02954624, 0x07574fd0,
				0x0cf79d59, 0x07396756, 0x016f3154, 0x0009df66,
			},
			[16]uint32{
				0x0bcdc5cd, 0x0492d355, 0x09d9d8a5, 0x01fea4f6,
				0x0081e336, 0x0697e45b, 0x0c712575, 0x0e7b112b,
				0x08fdb73a, 0x06ae6268, 0x0c271c2a, 0x084b467f,
				0x0155f3e6, 0x054cf783, 0x0b453295, 0x042c22ff,
			},
		),
		// d
		ed448.NewPoint(
			[16]uint32{
				0x03aee5b7, 0x032b3f7f, 0x06176ed0, 0x056fa571,
				0x04d01a0b, 0x0b382fa3, 0x03d55289, 0x04c8e69c,
				0x0ab17cae, 0x07b995ce, 0x03263f63, 0x08d4efc8,
				0x0382c935, 0x0587fbd5, 0x03d42439, 0x0b6979c9,
			},
			[16]uint32{
				0x070e385a, 0x04b3e06c, 0x0d8e3b40, 0x04064fff,
				0x04c1ae53, 0x0348a758, 0x04fa81f9, 0x06ef7f5a,
				0x0be2c435, 0x0b6c6794, 0x0159c719, 0x0350c7e1,
				0x0a5d1620, 0x0c9e7983, 0x0c90bd0e, 0x01196a72,
			},
			[16]uint32{
				0x0174aff6, 0x0aa1703e, 0x0b3d41e7, 0x0d68f123,
				0x0fcc832b, 0x0c11adbe, 0x0faecb96, 0x0152998d,
				0x0902ed06, 0x03560403, 0x067b0008, 0x0825eef3,
				0x0bb42471, 0x0ae05b98, 0x06c93c9b, 0x0bb36c4b,
			},
			[16]uint32{
				0x0970457b, 0x0bbb1746, 0x065927c4, 0x012c45ac,
				0x03a587e6, 0x095e2a6c, 0x0ec77f11, 0x09226042,
				0x0c304e97, 0x01783fbf, 0x0f4f1dbd, 0x07628142,
				0x0981f1fd, 0x0311dbc5, 0x05c12822, 0x033e76b1,
			},
		),
		// h
		ed448.NewPoint(
			[16]uint32{
				0x06808e72, 0x0ce35b11, 0x0e5e2f5c, 0x0b88b4d4,
				0x0869c12a, 0x04414132, 0x0bb898a8, 0x07c1e17c,
				0x0f04e50e, 0x068bad3b, 0x05c8d2b1, 0x0682f5cb,
				0x0a6b80e2, 0x0519b3a5, 0x045b7bec, 0x02b1b0d6,
			},
			[16]uint32{
				0x059d303a, 0x072683d3, 0x01b3a38d, 0x0b73118c,
				0x05dc7e0e, 0x0cd643d7, 0x09575347, 0x0e7653ae,
				0x0c59d3e1, 0x00d2a8d6, 0x0d9d3cb6, 0x0539c8ab,
				0x0d2cdc35, 0x03e95ff4, 0x0ca0a361, 0x0d6b571f,
			},
			[16]uint32{
				0x028916ca, 0x024a5ca9, 0x0ff426c7, 0x093dda43,
				0x0781af41, 0x07ec215e, 0x0e3deaef, 0x05963af4,
				0x0f1db9f4, 0x0018b7b8, 0x020b8cb8, 0x0e497381,
				0x0b98d304, 0x0750e83f, 0x00d61916, 0x0f0809f0,
			},
			[16]uint32{
				0x04b92c3b, 0x0d44025b, 0x09d68237, 0x0efa91f3,
				0x080def8c, 0x08703dcb, 0x0e39b56a, 0x0e3017a0,
				0x05ecb8cc, 0x0cd53123, 0x0c69b8db, 0x0fde3887,
				0x0cb571d9, 0x0e0580f7, 0x0b44788e, 0x087c0443,
			},
		),
	}

	serPubA = []byte{
		0x00, 0x10, 0xd6, 0xbb, 0xa4, 0x32, 0xfa, 0xd4,
		0x88, 0xde, 0x31, 0x3b, 0x61, 0xcb, 0x30, 0xdf,
		0xc1, 0x76, 0xba, 0xc5, 0x9a, 0x12, 0xc7, 0x8c,
		0x36, 0xa5, 0x69, 0x13, 0xa8, 0x5b, 0xb1, 0x80,
		0xe3, 0x5c, 0x29, 0x15, 0x5b, 0xee, 0x22, 0x26,
		0xdb, 0x35, 0x0f, 0x1d, 0xcc, 0x77, 0x5f, 0x50,
		0x84, 0x61, 0x19, 0x37, 0x85, 0x4e, 0x9b, 0xa2,
		0xc2, 0x22, 0xf2, 0x9c, 0x02, 0x67, 0x76, 0xa2,
		0xbe, 0xaf, 0x31, 0x5d, 0x00, 0x1a, 0x01, 0x30,
		0xc0, 0xb8, 0xba, 0x04, 0xf3, 0xa7, 0x9f, 0xae,
		0xf2, 0x78, 0x00, 0x8b, 0x5d, 0x58, 0xa4, 0x13,
		0xd1, 0xee, 0xb4, 0x8b, 0xb5, 0x83, 0x06, 0x1e,
		0x6d, 0xae, 0x28, 0x04, 0x4e, 0x38, 0xb7, 0x5d,
		0x32, 0x0e, 0xff, 0x20, 0xae, 0x2a, 0xbf, 0x4e,
		0xdb, 0x44, 0xd8, 0x8c, 0xc8, 0xae, 0x88, 0xeb,
		0xcb, 0xbd, 0x73, 0xcc, 0x8c, 0x4c, 0x87, 0xc8,
		0xd8, 0x0d, 0x27, 0x7e, 0xb3, 0xd8, 0xe1, 0x1d,
		0x55, 0x35, 0xdf, 0x42, 0x38, 0xf2, 0x4f, 0x65,
		0xf5, 0x31, 0xc1, 0x35, 0x3b, 0x6a, 0x3a, 0x0a,
		0x7b, 0x3b, 0x6d, 0x4c, 0x6e, 0xd7, 0xfc, 0x53,
		0xa0, 0x3b, 0xba, 0xfe, 0xda, 0x5b, 0xd1, 0x63,
		0x8d, 0x3a,
	}
)

func hexToBytes(s string) []byte {
	bytes, _ := hex.DecodeString(s)
	return bytes
}

func (s *CSSuite) Test_DerivePrivateKey(c *C) {
	expPriv := &PrivateKey{
		// x1
		ed448.NewScalar([]byte{
			0xc6, 0xd0, 0x98, 0x2e, 0xe4, 0xe5, 0x81, 0xe4,
			0x61, 0x3c, 0x46, 0x99, 0x0a, 0x37, 0x79, 0xc3,
			0xfa, 0xe5, 0xd5, 0x29, 0x27, 0x31, 0xa3, 0x55,
			0x9f, 0x34, 0x91, 0xd1, 0x0c, 0x7f, 0x88, 0x56,
			0x8c, 0x62, 0xe1, 0x86, 0xb7, 0xef, 0xd6, 0xcb,
			0x1b, 0x14, 0x88, 0x3b, 0xc0, 0xfb, 0xac, 0x46,
			0x0c, 0xc7, 0x20, 0x82, 0x3e, 0xd0, 0xdc, 0x2c,
		}),
		// x2
		ed448.NewScalar([]byte{
			0x7d, 0xbc, 0x55, 0xd7, 0xab, 0x95, 0xd3, 0xca,
			0xb7, 0x40, 0x1f, 0x64, 0xf4, 0xd3, 0x60, 0x2b,
			0xa0, 0xec, 0xed, 0x92, 0x90, 0xf7, 0xc4, 0x5c,
			0x51, 0xd0, 0x22, 0xd7, 0x5e, 0xf1, 0xee, 0x6c,
			0xd3, 0xf9, 0x2b, 0xea, 0xbf, 0x49, 0x94, 0xda,
			0xa5, 0x2c, 0x3b, 0x77, 0xdc, 0x98, 0x0c, 0xc6,
			0x36, 0xdf, 0xb9, 0x49, 0x7b, 0x54, 0x70, 0x05,
		}),
		// y1
		ed448.NewScalar([]byte{
			0xa5, 0x08, 0xbe, 0x0a, 0x34, 0x92, 0x1b, 0xfc,
			0x23, 0x3e, 0xb1, 0x4b, 0x82, 0x75, 0xa1, 0x9b,
			0x52, 0x85, 0xa6, 0xc5, 0x29, 0x59, 0x4a, 0x5e,
			0xe6, 0x1b, 0x69, 0xa0, 0x47, 0xf9, 0xcf, 0xed,
			0xa9, 0xfa, 0x15, 0xd3, 0x5f, 0x16, 0x11, 0xe7,
			0xa1, 0x84, 0x33, 0x1b, 0x07, 0x84, 0x18, 0x6c,
			0x6a, 0xb0, 0xfa, 0xdb, 0x95, 0x82, 0x26, 0x2c,
		}),
		// y2
		ed448.NewScalar([]byte{
			0x8b, 0xa2, 0xa9, 0x1a, 0xf1, 0x0b, 0x04, 0x96,
			0x92, 0xf9, 0xd5, 0x97, 0x27, 0x96, 0x6c, 0x8f,
			0x55, 0x6e, 0xf8, 0xdc, 0x85, 0x77, 0xf6, 0x66,
			0x46, 0xf4, 0x2a, 0xcd, 0x8e, 0x42, 0x83, 0xd8,
			0xd2, 0x95, 0xed, 0xc7, 0x24, 0x19, 0x72, 0xf6,
			0xe2, 0xdd, 0x3e, 0x21, 0x3e, 0x3a, 0x35, 0x65,
			0xfc, 0x78, 0x2c, 0x50, 0xfd, 0x0b, 0xfe, 0x1c,
		}),
		// z
		ed448.NewScalar([]byte{
			0x5b, 0x39, 0x3a, 0xce, 0x70, 0xc2, 0x97, 0x9c,
			0x78, 0x00, 0x74, 0xb9, 0x79, 0xac, 0xfb, 0xff,
			0xa7, 0xb8, 0x5c, 0x64, 0x6b, 0x5a, 0x4d, 0xb3,
			0x59, 0x1b, 0x31, 0x20, 0x4d, 0xdb, 0x16, 0xa5,
			0xf9, 0xb2, 0x88, 0x69, 0x13, 0xf1, 0xb1, 0xf1,
			0x4e, 0x5c, 0x05, 0x2f, 0x9e, 0xed, 0x3e, 0xf0,
			0x6f, 0xe8, 0x4e, 0x81, 0x49, 0x31, 0xfe, 0x3b,
		}),
	}
	priv, err := derivePrivKey(FixedRand(csRandData))
	c.Assert(priv, DeepEquals, expPriv)
	c.Assert(err, IsNil)

	r := make([]byte, 55)
	_, err = GenerateKeys(FixedRand(r))

	c.Assert(err, ErrorMatches, "cannot source enough entropy")
}

func (s *CSSuite) Test_KeyGeneration(c *C) {
	expPub := &PublicKey{
		// c
		ed448.NewPoint(
			[16]uint32{
				0x03ec8f96, 0x0d40670b, 0x0ac03fe7, 0x0956b651,
				0x0145e610, 0x03c89f01, 0x0a22e379, 0x0b0f5279,
				0x07fe2e6b, 0x0053b1ba, 0x072b1f72, 0x0cb078af,
				0x035a049b, 0x07e768e3, 0x01860b6a, 0x0762aebf,
			},
			[16]uint32{
				0x0c5319c5, 0x0a858447, 0x09609079, 0x02b2d222,
				0x0b3d6a8d, 0x041554d7, 0x0baf026e, 0x0129aac5,
				0x0b69553c, 0x04318fb5, 0x0ef1fc50, 0x07f45076,
				0x00d3c501, 0x0ef75db9, 0x008a0370, 0x095a0f3d,
			},
			[16]uint32{
				0x0550719b, 0x0597cebc, 0x0b44b3a7, 0x02dd5c82,
				0x0709fbe3, 0x0dcd450f, 0x013e75ec, 0x08a35968,
				0x02d1073c, 0x0731abc2, 0x0e1abb8e, 0x01e01b38,
				0x00c8a515, 0x0fa7ff47, 0x05ec3cc5, 0x0efe9e8e,
			},
			[16]uint32{
				0x01d3e461, 0x0a4f4114, 0x06f31b7e, 0x02fe6996,
				0x0f0602a8, 0x0d550a82, 0x00aaea26, 0x0e741792,
				0x0d0d9c93, 0x0847f70c, 0x0fd814b1, 0x022a9768,
				0x095cd0e3, 0x0ade222d, 0x06835bbd, 0x00ae74fa,
			},
		),
		// d
		ed448.NewPoint(
			[16]uint32{
				0x04cc98b8, 0x0aee5526, 0x0deec7ca, 0x03b955ca,
				0x0c9aa144, 0x05a7672d, 0x08f5f53b, 0x03a6963f,
				0x01ea8ec4, 0x0f42b22c, 0x08d7f50d, 0x08ef4899,
				0x029c4fa5, 0x0e5d32f8, 0x0e0f2f1b, 0x0bfc8d3c,
			},
			[16]uint32{
				0x0ee0f693, 0x01e5d3ef, 0x009e0f46, 0x0cd9d776,
				0x0f2c11fa, 0x0d424328, 0x04ace98d, 0x09574f9e,
				0x0f04b094, 0x0c23e744, 0x0cf292c7, 0x09f7df44,
				0x0be029ce, 0x0a60f67d, 0x0797fbf3, 0x0bbb568c,
			},
			[16]uint32{
				0x0f7be5f8, 0x09b2c468, 0x05104f8d, 0x0a4deedc,
				0x0221a851, 0x094b06f2, 0x0185d125, 0x08e747f2,
				0x00b4d17f, 0x0230798a, 0x046de54d, 0x0323e7bc,
				0x09d43f4c, 0x023ee2a9, 0x0af88db3, 0x0672cc85,
			},
			[16]uint32{
				0x049fc147, 0x00ecb653, 0x0fb574a7, 0x03eff8d7,
				0x05b6a752, 0x069d5481, 0x09719845, 0x0a436b44,
				0x05230555, 0x09851029, 0x044f9c9d, 0x069d289f,
				0x0b9314a4, 0x0f35dd2f, 0x0e8e816a, 0x00355c7d,
			},
		),
		// h
		ed448.NewPoint(
			[16]uint32{
				0x0dc2c86b, 0x062aa269, 0x04784c9d, 0x01750bcf,
				0x00683731, 0x0b198881, 0x0a36ee98, 0x0c24e6cb,
				0x0669a4ce, 0x01980f31, 0x0b1e6f4c, 0x08bdd701,
				0x08d950a1, 0x07bb8ae8, 0x0840a4e0, 0x01cef363,
			},
			[16]uint32{
				0x01ce8ca2, 0x0cc89a87, 0x0188519f, 0x092cebb4,
				0x097a3274, 0x0dbee214, 0x0bdd1dd3, 0x0271ec23,
				0x0d28e056, 0x02c21b7e, 0x0f60b334, 0x0e4b4223,
				0x0f473d83, 0x089718a9, 0x0b075869, 0x0700c433,
			},
			[16]uint32{
				0x035cd394, 0x07926b4e, 0x01d6652e, 0x0baacce0,
				0x0a29339d, 0x08b71b6a, 0x088184c8, 0x099a6fc8,
				0x0d8abc38, 0x0055c583, 0x0bcf735e, 0x03df44e4,
				0x06928a16, 0x0ef21a23, 0x00234218, 0x007d2dd1,
			},
			[16]uint32{
				0x0fb7cd8c, 0x0a32ac22, 0x03199605, 0x0607c466,
				0x0eddad7f, 0x08a71cfc, 0x066944f7, 0x020576e5,
				0x03202796, 0x0138fefd, 0x038b840f, 0x00272913,
				0x0c3082e6, 0x07d44546, 0x0b332340, 0x0b6f354d,
			},
		),
	}

	expPriv := &PrivateKey{
		// x1
		ed448.NewScalar([]byte{
			0xc6, 0xd0, 0x98, 0x2e, 0xe4, 0xe5, 0x81, 0xe4,
			0x61, 0x3c, 0x46, 0x99, 0x0a, 0x37, 0x79, 0xc3,
			0xfa, 0xe5, 0xd5, 0x29, 0x27, 0x31, 0xa3, 0x55,
			0x9f, 0x34, 0x91, 0xd1, 0x0c, 0x7f, 0x88, 0x56,
			0x8c, 0x62, 0xe1, 0x86, 0xb7, 0xef, 0xd6, 0xcb,
			0x1b, 0x14, 0x88, 0x3b, 0xc0, 0xfb, 0xac, 0x46,
			0x0c, 0xc7, 0x20, 0x82, 0x3e, 0xd0, 0xdc, 0x2c,
		}),
		// x2
		ed448.NewScalar([]byte{
			0x7d, 0xbc, 0x55, 0xd7, 0xab, 0x95, 0xd3, 0xca,
			0xb7, 0x40, 0x1f, 0x64, 0xf4, 0xd3, 0x60, 0x2b,
			0xa0, 0xec, 0xed, 0x92, 0x90, 0xf7, 0xc4, 0x5c,
			0x51, 0xd0, 0x22, 0xd7, 0x5e, 0xf1, 0xee, 0x6c,
			0xd3, 0xf9, 0x2b, 0xea, 0xbf, 0x49, 0x94, 0xda,
			0xa5, 0x2c, 0x3b, 0x77, 0xdc, 0x98, 0x0c, 0xc6,
			0x36, 0xdf, 0xb9, 0x49, 0x7b, 0x54, 0x70, 0x05,
		}),
		// y1
		ed448.NewScalar([]byte{
			0xa5, 0x08, 0xbe, 0x0a, 0x34, 0x92, 0x1b, 0xfc,
			0x23, 0x3e, 0xb1, 0x4b, 0x82, 0x75, 0xa1, 0x9b,
			0x52, 0x85, 0xa6, 0xc5, 0x29, 0x59, 0x4a, 0x5e,
			0xe6, 0x1b, 0x69, 0xa0, 0x47, 0xf9, 0xcf, 0xed,
			0xa9, 0xfa, 0x15, 0xd3, 0x5f, 0x16, 0x11, 0xe7,
			0xa1, 0x84, 0x33, 0x1b, 0x07, 0x84, 0x18, 0x6c,
			0x6a, 0xb0, 0xfa, 0xdb, 0x95, 0x82, 0x26, 0x2c,
		}),
		// y2
		ed448.NewScalar([]byte{
			0x8b, 0xa2, 0xa9, 0x1a, 0xf1, 0x0b, 0x04, 0x96,
			0x92, 0xf9, 0xd5, 0x97, 0x27, 0x96, 0x6c, 0x8f,
			0x55, 0x6e, 0xf8, 0xdc, 0x85, 0x77, 0xf6, 0x66,
			0x46, 0xf4, 0x2a, 0xcd, 0x8e, 0x42, 0x83, 0xd8,
			0xd2, 0x95, 0xed, 0xc7, 0x24, 0x19, 0x72, 0xf6,
			0xe2, 0xdd, 0x3e, 0x21, 0x3e, 0x3a, 0x35, 0x65,
			0xfc, 0x78, 0x2c, 0x50, 0xfd, 0x0b, 0xfe, 0x1c,
		}),
		// z
		ed448.NewScalar([]byte{
			0x5b, 0x39, 0x3a, 0xce, 0x70, 0xc2, 0x97, 0x9c,
			0x78, 0x00, 0x74, 0xb9, 0x79, 0xac, 0xfb, 0xff,
			0xa7, 0xb8, 0x5c, 0x64, 0x6b, 0x5a, 0x4d, 0xb3,
			0x59, 0x1b, 0x31, 0x20, 0x4d, 0xdb, 0x16, 0xa5,
			0xf9, 0xb2, 0x88, 0x69, 0x13, 0xf1, 0xb1, 0xf1,
			0x4e, 0x5c, 0x05, 0x2f, 0x9e, 0xed, 0x3e, 0xf0,
			0x6f, 0xe8, 0x4e, 0x81, 0x49, 0x31, 0xfe, 0x3b,
		}),
	}

	keyPair, err := GenerateKeys(FixedRand(csRandData))
	c.Assert(expPub.c, DeepEquals, keyPair.pub.c)
	c.Assert(expPub.d, DeepEquals, keyPair.pub.d)
	c.Assert(expPub.h, DeepEquals, keyPair.pub.h)
	c.Assert(err, IsNil)

	c.Assert(expPriv.x1, DeepEquals, keyPair.priv.x1)
	c.Assert(expPriv.x2, DeepEquals, keyPair.priv.x2)
	c.Assert(expPriv.y1, DeepEquals, keyPair.priv.y1)
	c.Assert(expPriv.y2, DeepEquals, keyPair.priv.y2)
	c.Assert(expPriv.z, DeepEquals, keyPair.priv.z)

	keyPair, err = GenerateKeys(FixedRand([]byte{0x00}))

	c.Assert(err, ErrorMatches, "cannot source enough entropy")
	c.Assert(keyPair, IsNil)
}

func (s *CSSuite) Test_Encryption(c *C) {
	randData := []byte{
		0xd5, 0xde, 0xed, 0x1a, 0xef, 0x64, 0xee, 0x90,
		0xab, 0xae, 0xbd, 0x66, 0xda, 0xe9, 0x9b, 0xe0,
		0xe9, 0x7e, 0xab, 0x4d, 0x8a, 0xd0, 0xbb, 0x9c,
		0xd1, 0xef, 0xde, 0x06, 0x95, 0x91, 0xf6, 0xed,
		0xb2, 0x43, 0xab, 0x41, 0x26, 0x1d, 0x27, 0xd4,
		0xb4, 0x6d, 0xa5, 0x37, 0xb3, 0x39, 0x7a, 0x5a,
		0x74, 0xb4, 0x2b, 0x72, 0xb5, 0x4d, 0xfe, 0x08,
	}

	message := []byte{
		0xfd, 0xf1, 0x18, 0xbf, 0x8e, 0xc9, 0x64, 0xc7,
		0x94, 0x46, 0x49, 0xda, 0xcd, 0xac, 0x2c, 0xff,
		0x72, 0x5e, 0xb7, 0x61, 0x46, 0xf1, 0x93, 0xa6,
		0x70, 0x81, 0x64, 0x37, 0x7c, 0xec, 0x6c, 0xe5,
		0xc6, 0x8d, 0x8f, 0xa0, 0x43, 0x23, 0x45, 0x33,
		0x73, 0x79, 0xa6, 0x48, 0x57, 0xbb, 0x0f, 0x70,
		0x63, 0x8c, 0x62, 0x26, 0x9e, 0x17, 0x5d, 0x22,
	}

	pub := &PublicKey{
		// c
		ed448.NewPoint(
			[16]uint32{
				0x0d1a3bb0, 0x0d4ed3d5, 0x0bee72e7, 0x07a57757,
				0x033114fb, 0x0af889a9, 0x07a4915e, 0x051f6631,
				0x0ee14f8d, 0x02fd5f70, 0x08811f82, 0x0fffb838,
				0x0f531141, 0x0130c68e, 0x011fa21d, 0x0730a635,
			},
			[16]uint32{
				0x0e731b10, 0x06225b69, 0x0a0fcf44, 0x0e8f3bf3,
				0x0896c850, 0x07d1d0a0, 0x0a3643b4, 0x0344cdcb,
				0x0e744b0a, 0x08b7171a, 0x08b8ecd5, 0x0913c73a,
				0x0f0e91a6, 0x0fa87618, 0x0f53f773, 0x096ec324,
			},
			[16]uint32{
				0x0236cc03, 0x02cae89f, 0x0fa2201a, 0x0f50f406,
				0x067620d3, 0x0835ebbc, 0x01ec4469, 0x07568d88,
				0x0323640e, 0x0e0fcc51, 0x06b8c60c, 0x0758f2c4,
				0x0ca64f94, 0x0df17830, 0x0f12e81c, 0x0a22c62f,
			},
			[16]uint32{
				0x0f0a7999, 0x05faf1c5, 0x04474254, 0x01bf3e07,
				0x09634366, 0x0431a64e, 0x01b2779e, 0x08ab476c,
				0x0f69a009, 0x01a86bac, 0x0ddf3e82, 0x084f551b,
				0x0c0476fe, 0x0051fbcc, 0x05241871, 0x05969360,
			},
		),
		// d
		ed448.NewPoint(
			[16]uint32{
				0x0d1a3bb0, 0x0d4ed3d5, 0x0bee72e7, 0x07a57757,
				0x033114fb, 0x0af889a9, 0x07a4915e, 0x051f6631,
				0x0ee14f8d, 0x02fd5f70, 0x08811f82, 0x0fffb838,
				0x0f531141, 0x0130c68e, 0x011fa21d, 0x0730a635,
			},
			[16]uint32{
				0x0e731b10, 0x06225b69, 0x0a0fcf44, 0x0e8f3bf3,
				0x0896c850, 0x07d1d0a0, 0x0a3643b4, 0x0344cdcb,
				0x0e744b0a, 0x08b7171a, 0x08b8ecd5, 0x0913c73a,
				0x0f0e91a6, 0x0fa87618, 0x0f53f773, 0x096ec324,
			},
			[16]uint32{
				0x0236cc03, 0x02cae89f, 0x0fa2201a, 0x0f50f406,
				0x067620d3, 0x0835ebbc, 0x01ec4469, 0x07568d88,
				0x0323640e, 0x0e0fcc51, 0x06b8c60c, 0x0758f2c4,
				0x0ca64f94, 0x0df17830, 0x0f12e81c, 0x0a22c62f,
			},
			[16]uint32{
				0x0f0a7999, 0x05faf1c5, 0x04474254, 0x01bf3e07,
				0x09634366, 0x0431a64e, 0x01b2779e, 0x08ab476c,
				0x0f69a009, 0x01a86bac, 0x0ddf3e82, 0x084f551b,
				0x0c0476fe, 0x0051fbcc, 0x05241871, 0x05969360,
			},
		),
		// h
		ed448.NewPoint(
			[16]uint32{
				0x03dcc290, 0x0c997800, 0x03ccf175, 0x0f6d5cca,
				0x0c39f63d, 0x087e19c3, 0x0015f977, 0x0f5ac8ea,
				0x0025900b, 0x049af15a, 0x036d30d9, 0x00e8a4a5,
				0x092085ea, 0x0ed2cdd7, 0x0b9a5ab6, 0x0dce53c5,
			},
			[16]uint32{
				0x09e68bde, 0x0fc1025b, 0x0940ad81, 0x0f607940,
				0x03581b48, 0x0ddf609a, 0x0b1e3cc3, 0x042665f3,
				0x0ec0569a, 0x0445a714, 0x007fe1f2, 0x0e8af1a9,
				0x0f432c2a, 0x0a456054, 0x06dcfc13, 0x0bfd6853,
			},
			[16]uint32{
				0x0fdb7132, 0x0fc94fb3, 0x0f54cbda, 0x02fe2aed,
				0x0d592362, 0x03217544, 0x0bf9b081, 0x0619628e,
				0x09a377f6, 0x0bb30a69, 0x0fa2dddd, 0x037190cf,
				0x01b73e76, 0x02253287, 0x0183881c, 0x08212151,
			},
			[16]uint32{
				0x07507a9d, 0x0edfff2a, 0x0f81885e, 0x0ef133d0,
				0x05d7e8ec, 0x0dd531b2, 0x0cfff6a4, 0x0e58ed2b,
				0x0aacca3d, 0x03fa90ed, 0x0808c373, 0x0a5b35f3,
				0x092effcc, 0x0790c7dd, 0x0cbf84c2, 0x0a177973,
			},
		),
	}

	expCSM := &CSMessage{
		// u1
		ed448.NewPoint(
			[16]uint32{
				0x01292e9b, 0x0d72d984, 0x0ba7d04d, 0x078be876,
				0x08e6a011, 0x021ad459, 0x0f22b90c, 0x0258a5f3,
				0x07a82841, 0x05bb2a02, 0x07de39ef, 0x0c9d56b6,
				0x0436a466, 0x0a9aac89, 0x047fd480, 0x048d4398,
			},
			[16]uint32{
				0x075e9cfa, 0x01eeb246, 0x0b867324, 0x076f7fa4,
				0x05cc6107, 0x07f780a0, 0x007dc4d8, 0x024ce5da,
				0x033a7566, 0x0324f425, 0x0ea0e1b6, 0x016dd7ac,
				0x0462a2f6, 0x0a83879e, 0x05f4ff61, 0x0b8ba82b,
			},
			[16]uint32{
				0x0287bef0, 0x038b9c9e, 0x06153cfb, 0x037c5a4a,
				0x0f9fc3ea, 0x0c9a91f7, 0x089520dc, 0x01194f90,
				0x0d2c188a, 0x0dffb7ff, 0x037c11eb, 0x0df7e980,
				0x09ff75db, 0x0f7b39af, 0x07b3eb7b, 0x07a1f44a,
			},
			[16]uint32{
				0x07c77db1, 0x05c32d6d, 0x04bd494e, 0x0196e99b,
				0x0457a51d, 0x03a284a1, 0x02513853, 0x0c776d58,
				0x04363fb2, 0x0f599f7c, 0x018ce56b, 0x0ac7edc2,
				0x01a2f684, 0x0d9c52ac, 0x07236fa1, 0x0b20c589,
			},
		),
		// u2
		ed448.NewPoint(
			[16]uint32{
				0x01cce907, 0x018df11d, 0x06b157f7, 0x0439d7de,
				0x0d3c1ace, 0x011e645f, 0x0cd621ec, 0x0a96adf6,
				0x052bef2e, 0x07e169a6, 0x0b795219, 0x0eeccf75,
				0x0160501c, 0x0d6f89be, 0x051c0a1c, 0x0b513c91,
			},
			[16]uint32{
				0x0f746a89, 0x06e8413d, 0x0988aacc, 0x01257e03,
				0x00a55cb3, 0x0f1f75a0, 0x0321d2bb, 0x0a5cc483,
				0x0c7b8786, 0x0b00b0f9, 0x0279b51b, 0x0514b6ac,
				0x097429af, 0x0ca4e0e9, 0x044a9371, 0x0794efea,
			},
			[16]uint32{
				0x04a9dddb, 0x068c85da, 0x0967d4c1, 0x0c708819,
				0x0054491c, 0x0ff57207, 0x026e0b3d, 0x0b2a34be,
				0x01c2d648, 0x0b97fe36, 0x0dca7e2a, 0x0a93d730,
				0x00f1c4bc, 0x0c1cf106, 0x000e24f3, 0x03951775,
			},
			[16]uint32{
				0x0b27f363, 0x0ebb724c, 0x08b041ec, 0x032b66fb,
				0x0dc3054a, 0x0e1867bb, 0x0c36110b, 0x0e183ba8,
				0x091808bd, 0x055534c8, 0x025964d3, 0x057159af,
				0x0e8920f9, 0x0cd7b5c7, 0x042a3088, 0x0370fa36,
			},
		),
		// e
		ed448.NewPoint(
			[16]uint32{
				0x0742d0c3, 0x05de45fe, 0x0f4e3eee, 0x0b9f7154,
				0x01ca08e6, 0x0b1b0335, 0x092a256d, 0x0612586e,
				0x0d961cc8, 0x07602dd0, 0x095519b0, 0x0e586bc1,
				0x058dce28, 0x0c59bb64, 0x0dcddee2, 0x0f6de3e2,
			},
			[16]uint32{
				0x04f7e0ce, 0x07e7c3cc, 0x05d5c27e, 0x01b30215,
				0x0846299b, 0x0617993d, 0x088b45ff, 0x02e461d6,
				0x01392188, 0x0fa07ad6, 0x0548a21b, 0x08ad8d21,
				0x0a15dd51, 0x0e81057e, 0x0de32596, 0x042e192b,
			},
			[16]uint32{
				0x0559952e, 0x0c61f700, 0x0e416b06, 0x018928f7,
				0x0b3239e6, 0x008c12ca, 0x02963d6c, 0x022fd021,
				0x0b11c27a, 0x06b764fa, 0x0ac9f8cf, 0x0d38a907,
				0x05e792cf, 0x00550d54, 0x00e1ad10, 0x015fe1f9,
			},
			[16]uint32{
				0x072ee832, 0x09927198, 0x08496f04, 0x067b9f7b,
				0x07f0b101, 0x0aacebd4, 0x0eb2663b, 0x064eda94,
				0x0d7991b3, 0x063657a1, 0x094ff9db, 0x07d2bc46,
				0x0a60abac, 0x0fdd6e57, 0x015f2220, 0x0c0a39b5,
			},
		),
		// v
		ed448.NewPoint(
			[16]uint32{
				0x0f0a5f34, 0x00ead59c, 0x04633a99, 0x0470f654,
				0x05c53fc2, 0x05e963c7, 0x05985c76, 0x0b9ae305,
				0x06d45156, 0x09791bc9, 0x0d9329c6, 0x0829c1d3,
				0x081069da, 0x0d077b07, 0x0ec06f4b, 0x07fc9b17,
			},
			[16]uint32{
				0x063e9252, 0x029079b8, 0x094eb61f, 0x03adc405,
				0x0f367d39, 0x01a0d3cb, 0x05fe9f77, 0x0467c437,
				0x00603d5a, 0x0aa2cb44, 0x0cfd6b17, 0x04206985,
				0x0e96f4d9, 0x00b9e7a4, 0x0c549850, 0x0d38f069,
			},
			[16]uint32{
				0x00f0db5f, 0x0a809f5d, 0x0b3353c0, 0x065c20a8,
				0x0494538c, 0x0c9a0f64, 0x004493c9, 0x03cb62f4,
				0x09ae662b, 0x0baa6809, 0x0561e7e6, 0x0f66c598,
				0x07f56e7e, 0x0abcbced, 0x0df7a986, 0x05c5c5e8,
			},
			[16]uint32{
				0x0ef81742, 0x0d834794, 0x09161d1c, 0x091984d2,
				0x0d81bfb4, 0x0d126602, 0x070ebc1e, 0x030bb6cc,
				0x0fdabdc6, 0x0d24aa9e, 0x01a3bd3a, 0x0603dfea,
				0x01f5c9c0, 0x0f49d7cf, 0x0f11e5b1, 0x021a23d9,
			},
		),
	}

	csm, err := Encrypt(message, FixedRand(randData), pub)

	c.Assert(csm, DeepEquals, expCSM)
	c.Assert(err, IsNil)

	csm, err = Encrypt(message, FixedRand([]byte{0x00}), pub)

	c.Assert(err, ErrorMatches, "cannot source enough entropy")
}

func (s *CSSuite) Test_Decryption(c *C) {
	cipher := &CSMessage{
		// u1
		ed448.NewPoint(
			[16]uint32{
				0x01292e9b, 0x0d72d984, 0x0ba7d04d, 0x078be876,
				0x08e6a011, 0x021ad459, 0x0f22b90c, 0x0258a5f3,
				0x07a82841, 0x05bb2a02, 0x07de39ef, 0x0c9d56b6,
				0x0436a466, 0x0a9aac89, 0x047fd480, 0x048d4398,
			},
			[16]uint32{
				0x075e9cfa, 0x01eeb246, 0x0b867324, 0x076f7fa4,
				0x05cc6107, 0x07f780a0, 0x007dc4d8, 0x024ce5da,
				0x033a7566, 0x0324f425, 0x0ea0e1b6, 0x016dd7ac,
				0x0462a2f6, 0x0a83879e, 0x05f4ff61, 0x0b8ba82b,
			},
			[16]uint32{
				0x0287bef0, 0x038b9c9e, 0x06153cfb, 0x037c5a4a,
				0x0f9fc3ea, 0x0c9a91f7, 0x089520dc, 0x01194f90,
				0x0d2c188a, 0x0dffb7ff, 0x037c11eb, 0x0df7e980,
				0x09ff75db, 0x0f7b39af, 0x07b3eb7b, 0x07a1f44a,
			},
			[16]uint32{
				0x07c77db1, 0x05c32d6d, 0x04bd494e, 0x0196e99b,
				0x0457a51d, 0x03a284a1, 0x02513853, 0x0c776d58,
				0x04363fb2, 0x0f599f7c, 0x018ce56b, 0x0ac7edc2,
				0x01a2f684, 0x0d9c52ac, 0x07236fa1, 0x0b20c589,
			},
		),
		// u2
		ed448.NewPoint(
			[16]uint32{
				0x01cce907, 0x018df11d, 0x06b157f7, 0x0439d7de,
				0x0d3c1ace, 0x011e645f, 0x0cd621ec, 0x0a96adf6,
				0x052bef2e, 0x07e169a6, 0x0b795219, 0x0eeccf75,
				0x0160501c, 0x0d6f89be, 0x051c0a1c, 0x0b513c91,
			},
			[16]uint32{
				0x0f746a89, 0x06e8413d, 0x0988aacc, 0x01257e03,
				0x00a55cb3, 0x0f1f75a0, 0x0321d2bb, 0x0a5cc483,
				0x0c7b8786, 0x0b00b0f9, 0x0279b51b, 0x0514b6ac,
				0x097429af, 0x0ca4e0e9, 0x044a9371, 0x0794efea,
			},
			[16]uint32{
				0x04a9dddb, 0x068c85da, 0x0967d4c1, 0x0c708819,
				0x0054491c, 0x0ff57207, 0x026e0b3d, 0x0b2a34be,
				0x01c2d648, 0x0b97fe36, 0x0dca7e2a, 0x0a93d730,
				0x00f1c4bc, 0x0c1cf106, 0x000e24f3, 0x03951775,
			},
			[16]uint32{
				0x0b27f363, 0x0ebb724c, 0x08b041ec, 0x032b66fb,
				0x0dc3054a, 0x0e1867bb, 0x0c36110b, 0x0e183ba8,
				0x091808bd, 0x055534c8, 0x025964d3, 0x057159af,
				0x0e8920f9, 0x0cd7b5c7, 0x042a3088, 0x0370fa36,
			},
		),
		// e
		ed448.NewPoint(
			[16]uint32{
				0x0742d0c3, 0x05de45fe, 0x0f4e3eee, 0x0b9f7154,
				0x01ca08e6, 0x0b1b0335, 0x092a256d, 0x0612586e,
				0x0d961cc8, 0x07602dd0, 0x095519b0, 0x0e586bc1,
				0x058dce28, 0x0c59bb64, 0x0dcddee2, 0x0f6de3e2,
			},
			[16]uint32{
				0x04f7e0ce, 0x07e7c3cc, 0x05d5c27e, 0x01b30215,
				0x0846299b, 0x0617993d, 0x088b45ff, 0x02e461d6,
				0x01392188, 0x0fa07ad6, 0x0548a21b, 0x08ad8d21,
				0x0a15dd51, 0x0e81057e, 0x0de32596, 0x042e192b,
			},
			[16]uint32{
				0x0559952e, 0x0c61f700, 0x0e416b06, 0x018928f7,
				0x0b3239e6, 0x008c12ca, 0x02963d6c, 0x022fd021,
				0x0b11c27a, 0x06b764fa, 0x0ac9f8cf, 0x0d38a907,
				0x05e792cf, 0x00550d54, 0x00e1ad10, 0x015fe1f9,
			},
			[16]uint32{
				0x072ee832, 0x09927198, 0x08496f04, 0x067b9f7b,
				0x07f0b101, 0x0aacebd4, 0x0eb2663b, 0x064eda94,
				0x0d7991b3, 0x063657a1, 0x094ff9db, 0x07d2bc46,
				0x0a60abac, 0x0fdd6e57, 0x015f2220, 0x0c0a39b5,
			},
		),
		// v
		ed448.NewPoint(
			[16]uint32{
				0x0f0a5f34, 0x00ead59c, 0x04633a99, 0x0470f654,
				0x05c53fc2, 0x05e963c7, 0x05985c76, 0x0b9ae305,
				0x06d45156, 0x09791bc9, 0x0d9329c6, 0x0829c1d3,
				0x081069da, 0x0d077b07, 0x0ec06f4b, 0x07fc9b17,
			},
			[16]uint32{
				0x063e9252, 0x029079b8, 0x094eb61f, 0x03adc405,
				0x0f367d39, 0x01a0d3cb, 0x05fe9f77, 0x0467c437,
				0x00603d5a, 0x0aa2cb44, 0x0cfd6b17, 0x04206985,
				0x0e96f4d9, 0x00b9e7a4, 0x0c549850, 0x0d38f069,
			},
			[16]uint32{
				0x00f0db5f, 0x0a809f5d, 0x0b3353c0, 0x065c20a8,
				0x0494538c, 0x0c9a0f64, 0x004493c9, 0x03cb62f4,
				0x09ae662b, 0x0baa6809, 0x0561e7e6, 0x0f66c598,
				0x07f56e7e, 0x0abcbced, 0x0df7a986, 0x05c5c5e8,
			},
			[16]uint32{
				0x0ef81742, 0x0d834794, 0x09161d1c, 0x091984d2,
				0x0d81bfb4, 0x0d126602, 0x070ebc1e, 0x030bb6cc,
				0x0fdabdc6, 0x0d24aa9e, 0x01a3bd3a, 0x0603dfea,
				0x01f5c9c0, 0x0f49d7cf, 0x0f11e5b1, 0x021a23d9,
			},
		),
	}

	priv := &PrivateKey{
		// x1
		ed448.NewScalar([]byte{
			0xc1, 0xd9, 0xe2, 0xfb, 0xb1, 0x30, 0x6d, 0x08,
			0x56, 0xbb, 0x23, 0xb3, 0x48, 0xd1, 0x41, 0xeb,
			0xe2, 0x33, 0x17, 0x6b, 0x95, 0x73, 0xc3, 0x8d,
			0x11, 0x78, 0x30, 0x2b, 0x80, 0xef, 0x0d, 0xdd,
			0xcc, 0x47, 0xeb, 0x8a, 0xa6, 0xe0, 0xa3, 0x1d,
			0xc5, 0x25, 0xd5, 0x47, 0x27, 0x82, 0x65, 0x8a,
			0xe6, 0x72, 0xa2, 0x1b, 0xed, 0x2b, 0x8a, 0x3d,
		}),
		// x2
		ed448.NewScalar([]byte{
			0x8b, 0x3b, 0xd8, 0xe5, 0xe3, 0x16, 0x41, 0x17,
			0x57, 0x1a, 0x2d, 0xdc, 0x07, 0x1b, 0xe9, 0x7f,
			0x89, 0x07, 0xcc, 0xb7, 0x6d, 0x42, 0x87, 0x65,
			0x69, 0x3c, 0x03, 0x7d, 0x24, 0x40, 0xd9, 0x68,
			0xa7, 0x73, 0x3b, 0x17, 0x5b, 0xa8, 0x3b, 0x75,
			0x47, 0x84, 0x68, 0x1a, 0xcc, 0x17, 0xeb, 0xfb,
			0x03, 0x1a, 0xce, 0x13, 0x8b, 0xb4, 0x9f, 0x16,
		}),
		// y1
		ed448.NewScalar([]byte{
			0xdc, 0xbb, 0xc2, 0xc1, 0x38, 0xdd, 0xc2, 0x1b,
			0xb3, 0x75, 0x6f, 0x67, 0xb7, 0xdb, 0x3a, 0x90,
			0x1b, 0x6e, 0x47, 0x5b, 0xe8, 0xe4, 0x72, 0x88,
			0xf4, 0xec, 0x24, 0x38, 0x75, 0x3b, 0x6f, 0x79,
			0x78, 0xcc, 0x84, 0x48, 0xd3, 0x07, 0xb9, 0xfe,
			0x5e, 0x8a, 0xb8, 0xf2, 0xe7, 0xb2, 0x41, 0xf0,
			0xde, 0xea, 0xba, 0xf5, 0x25, 0x2e, 0x6c, 0x2f,
		}),
		// y2
		ed448.NewScalar([]byte{
			0xf9, 0xa7, 0x3c, 0x16, 0x0d, 0xa9, 0xf3, 0x3e,
			0x41, 0x41, 0x88, 0x90, 0x69, 0x5d, 0x4d, 0x55,
			0xa7, 0x9b, 0x9d, 0x88, 0x6e, 0x3c, 0xc8, 0x7e,
			0x0e, 0x7b, 0x07, 0x14, 0x1a, 0x57, 0x1c, 0x18,
			0x80, 0xcb, 0x8a, 0x71, 0x91, 0xb1, 0xfe, 0x36,
			0xd2, 0x5e, 0x2f, 0x40, 0x06, 0x92, 0x00, 0x31,
			0xa0, 0x46, 0xd8, 0x1a, 0xbc, 0x53, 0x83, 0x2f,
		}),
		// z
		ed448.NewScalar([]byte{
			0x13, 0xa6, 0x7f, 0x47, 0xa4, 0x42, 0xbb, 0x3a,
			0x08, 0xd4, 0x8c, 0x9a, 0x2c, 0x4b, 0xca, 0xf5,
			0xbc, 0xb7, 0xd9, 0x13, 0x6a, 0x96, 0x14, 0xf0,
			0x23, 0xf5, 0x7f, 0x8e, 0x86, 0x50, 0x3d, 0xf7,
			0x0e, 0x0b, 0xf3, 0x92, 0x3c, 0x83, 0x41, 0x43,
			0x1b, 0x0b, 0x13, 0x66, 0xac, 0x06, 0x94, 0x30,
			0x22, 0xbf, 0x2e, 0x24, 0x2e, 0x76, 0x52, 0x0a,
		}),
	}

	_, err := Decrypt(priv, cipher)
	c.Assert(err, ErrorMatches, "cannot decrypt the message")
}

func (s *CSSuite) Test_EncryptAndDecrypt(c *C) {
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
	csm, err := Encrypt(message, rand.Reader, keyPair.pub)
	expMessage, err := Decrypt(keyPair.priv, csm)

	c.Assert(expMessage, DeepEquals, message)
	c.Assert(err, IsNil)
}
