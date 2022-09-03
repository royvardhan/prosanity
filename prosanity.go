package prosanity

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/farces/mt19937_64"
)

const TotalSeedCount = 1 << 32

var Curve = secp256k1.S256()

func PublicKeyFromSeed(seed uint32) uint64 {
	eng := mt19937_64.New()
	eng.Seed(int64(seed))

	var r [32]byte
	binary.BigEndian.PutUint64(r[24:], uint64(eng.Int63()))
	binary.BigEndian.PutUint64(r[16:], uint64(eng.Int63()))
	binary.BigEndian.PutUint64(r[8:], uint64(eng.Int63()))
	binary.BigEndian.PutUint64(r[0:], uint64(eng.Int63()))

	X, _ := Curve.ScalarBaseMult(r[:])
	return X.Uint64()
}

func PrivateKRecover(seed uint32, batch, globalID uint64) []byte {
	eng := mt19937_64.New()
	eng.Seed(int64(seed))
	var k [32]byte
	binary.BigEndian.PutUint64(k[24:], uint64(eng.Int63())+batch+2)
	binary.BigEndian.PutUint64(k[16:], uint64(eng.Int63()))
	binary.BigEndian.PutUint64(k[8:], uint64(eng.Int63()))
	binary.BigEndian.PutUint64(k[0:], uint64(eng.Int63())+globalID)
	return k[:]
}

func GenDiffK(batch, globalID uint64) []byte {
	var b [32]byte
	binary.BigEndian.PutUint64(b[24:], batch+2)
	binary.BigEndian.PutUint64(b[16:], 0)
	binary.BigEndian.PutUint64(b[8:], 0)
	binary.BigEndian.PutUint64(b[:], globalID)
	return b[:]
}

func IDDiffK() []byte {
	var b [32]byte
	binary.BigEndian.PutUint64(b[24:], 0)
	binary.BigEndian.PutUint64(b[16:], 0)
	binary.BigEndian.PutUint64(b[8:], 0)
	binary.BigEndian.PutUint64(b[:], 1)
	return b[:]
}
