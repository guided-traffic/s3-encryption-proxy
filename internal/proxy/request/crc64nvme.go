package request

import (
	"encoding/binary"
	"hash"
)

// crc64NVMEPoly is the reflected CRC-64/NVME polynomial, the same constant
// aws-sdk-go-v2 uses for x-amz-checksum-crc64nvme.
const crc64NVMEPoly = 0x9a6c9329ac4bc9b5

// crc64NVMETable is built once at package load. hash/crc64 caches a slicing-by-8
// helper only for its own ISO and ECMA tables; for any other polynomial it
// rebuilds a 16 KiB helper on every sufficiently large Write, which at the
// decoder's read size is one allocation and an 8x256 build loop per read.
// BenchmarkCRC64NVMEWrite measures the difference against the naive form.
var crc64NVMETable = makeCRC64SlicingBy8(crc64NVMEPoly)

func makeCRC64SlicingBy8(poly uint64) *[8][256]uint64 {
	t := new([8][256]uint64)
	for i := 0; i < 256; i++ {
		crc := uint64(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		t[0][i] = crc
	}
	for i := 0; i < 256; i++ {
		crc := t[0][i]
		for j := 1; j < 8; j++ {
			crc = t[0][crc&0xff] ^ (crc >> 8)
			t[j][i] = crc
		}
	}
	return t
}

// crc64NVMEUpdate matches hash/crc64's semantics: the running value is
// complemented on the way in and out, so a zero seed means an all-ones initial
// register and an all-ones final xor.
func crc64NVMEUpdate(crc uint64, p []byte) uint64 {
	t := crc64NVMETable
	crc = ^crc
	for len(p) >= 8 {
		crc ^= binary.LittleEndian.Uint64(p)
		crc = t[7][crc&0xff] ^
			t[6][(crc>>8)&0xff] ^
			t[5][(crc>>16)&0xff] ^
			t[4][(crc>>24)&0xff] ^
			t[3][(crc>>32)&0xff] ^
			t[2][(crc>>40)&0xff] ^
			t[1][(crc>>48)&0xff] ^
			t[0][crc>>56]
		p = p[8:]
	}
	for _, v := range p {
		crc = t[0][byte(crc)^v] ^ (crc >> 8)
	}
	return ^crc
}

// crc64NVME is the hash.Hash the checksum registry hands out for
// x-amz-checksum-crc64nvme.
type crc64NVME struct{ crc uint64 }

func newCRC64NVME() hash.Hash { return &crc64NVME{} }

func (c *crc64NVME) Write(p []byte) (int, error) {
	c.crc = crc64NVMEUpdate(c.crc, p)
	return len(p), nil
}

func (c *crc64NVME) Sum(b []byte) []byte {
	return binary.BigEndian.AppendUint64(b, c.crc)
}

func (c *crc64NVME) Reset()         { c.crc = 0 }
func (c *crc64NVME) Size() int      { return 8 }
func (c *crc64NVME) BlockSize() int { return 1 }
