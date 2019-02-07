package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/davidminor/uint128"
	"time"
)

import "golang.org/x/crypto/sha3"

func getbit(x uint128.Uint128, i int) uint8 {
	var bit uint8
	if i < 64 {
		//fmt.Println(string(strconv.FormatUint(x.H, 2))[0])
		//fmt.Println(strconv.FormatUint(x.H, 2)[0])

		bit = fmt.Sprintf("%064b", x.H)[i]
	} else {
		bit = fmt.Sprintf("%064b", x.L)[i-64]
	}

	// uint 48 == 0 in binary
	if bit == 48 {
		return 0
	} else {
		return 1
	}
}

func randint128() uint128.Uint128 {
	/*
	Use crypto rand to generate a random 64 bit number
	 */

	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint128.Uint128{0, 0}
	}

	H := binary.LittleEndian.Uint64(b[:8])
	L := binary.LittleEndian.Uint64(b[8:16])

	return uint128.Uint128{H,L}
}

func PRG(seed uint128.Uint128) uint128.Uint128 {
	/*
	Use the given seed as a parameter to the PRG, hash it and output it
	 */

	h := make([]byte, 128)
	seedtohash := string(fmt.Sprintf("%v", seed))
	sha3.ShakeSum128(h, []byte(seedtohash))
	hH := uint64(binary.LittleEndian.Uint64(h[:64]))
	hL := uint64(binary.LittleEndian.Uint64(h[64:128]))

	return uint128.Uint128{hH, hL}

	/*rand.Seed(int64(seed.H))
	randH := rand.Uint64()
	randH2 := rand.Uint64()
	randH3 := rand.Uint64()
	randH4 := rand.Uint64()

	rand.Seed(int64(seed.L))
	randL := rand.Uint64()
	randL2 := rand.Uint64()
	randL3 := rand.Uint64()
	randL4 := rand.Uint64()

	return [3]uint128.Uint128{
		uint128.Uint128{randL^randH2, randH^randL2},
		uint128.Uint128{randL^randH3, randH^randL3},
		uint128.Uint128{randL^randH4, randH^randL4}}*/
}

func GenKey() ([128][2]uint128.Uint128, [128]uint128.Uint128) {
	var sk [128][2]uint128.Uint128
	var pk [128]uint128.Uint128

	for i := 0; i < 128; i++ {
		var s0 = randint128()
		var s1 = randint128()

		sk[i][0] = s0
		sk[i][1] = s1

		var pk0 = PRG(s0)
		var pk1 = PRG(s1)

		pk[i] = pk0.Xor(pk1)

	}
	return sk, pk
}

func GenTestRing(size int, pk [128]uint128.Uint128, position int) [][128]uint128.Uint128 {
	var ring = make([][128]uint128.Uint128, 0)

	for i := 0; i < size; i++ {
		if i == position {
			ring = append(ring, pk)
		} else {
			var pkj [128]uint128.Uint128
			for j := 0; j < 128; j++ {
				var pk = randint128()
				pkj[j] = pk
			}
			ring = append(ring, pkj)

		}
	}
	return ring
}

func RSign(
	ring [][128]uint128.Uint128,
	secret_key [128][2]uint128.Uint128,
	l int,
	message string) ([]uint128.Uint128, [][128]uint128.Uint128) {

	var r [][128]uint128.Uint128
	var x []uint128.Uint128
	var c [][128]uint128.Uint128


	for i := 0; i < len(ring); i++ {
		var ri [128]uint128.Uint128
		var ci [128]uint128.Uint128

		x = append(x, randint128())

		if i == l {
			for j := 0; j < 128; j++ {
				ci[j] = PRG(secret_key[j][0])
			}
		} else {
			for j := 0; j < 128; j++ {
				rij := randint128()
				prg_rij := PRG(rij)

				//bit at xi_j is 0
				if getbit(x[i], j) == 0 {
					ci[j] = prg_rij
				} else {
					ci[j] = prg_rij.Xor(ring[i][j])
				}
				ri[j] = rij
			}
		}
		c = append(c, ci)
		r = append(r, ri)
	}

	h := make([]byte, 128)
	tohash := string(fmt.Sprintf("%v%v%v", ring, message, c))
	sha3.ShakeSum128(h, []byte(tohash))
	hH := uint64(binary.LittleEndian.Uint64(h[:64]))
	hL := uint64(binary.LittleEndian.Uint64(h[64:128]))

	h2 := uint128.Uint128{hH, hL}

	xl := uint128.Uint128{0, 0}

	for i := 0; i < len(ring); i++ {
		if i != l {
			xl = x[i].Xor(xl)
		}
	}
	x[l] = xl.Xor(h2)

	for j := 0; j < 128; j++ {
		r[l][j] = secret_key[j][getbit(x[l], j)]
	}
	return x, r
}

func RVerify(ring [][128]uint128.Uint128,
	x []uint128.Uint128,
	r [][128]uint128.Uint128,
	message string) (bool) {

	var c [][128]uint128.Uint128
	for i := 0; i < len(ring); i++ {
		var ci [128]uint128.Uint128
		for j := 0; j < 128; j++ {
			prg_rij := PRG(r[i][j])
			if getbit(x[i], j) == 0 {
				ci[j] = prg_rij
			} else {
				ci[j] = prg_rij.Xor(ring[i][j])
			}

		}
		c = append(c, ci)
	}

	h := make([]byte, 128)
	tohash := string(fmt.Sprintf("%v%v%v", ring, message, c))
	sha3.ShakeSum128(h, []byte(tohash))
	hH := uint64(binary.LittleEndian.Uint64(h[:64]))
	hL := uint64(binary.LittleEndian.Uint64(h[64:128]))
	h2 := uint128.Uint128{hH, hL}

	xl := uint128.Uint128{0, 0}
	for i := 0; i < len(ring); i++ {
		xl = x[i].Xor(xl)

	}
	return xl == h2
}

func GetRunTime(ring_size int){
	message := "this is a message we'll sign"
	position := 0

	var sk, pk = GenKey()
	var ring = GenTestRing(ring_size, pk, position)


	sign_time := time.Now()
	x, r := RSign(ring, sk, position, message)
	sign_elapsed := time.Since(sign_time)

	verify_time := time.Now()
	RVerify(ring, x, r, message)
	verify_elapsed := time.Since(verify_time)
	fmt.Printf("%d, %s, %s\n", ring_size, sign_elapsed, verify_elapsed)

	//log.Printf("Ring size: %d, sign time: %s, verify time: %s", ring_size, sign_elapsed, verify_elapsed)
	//fmt.Println(x)
	//fmt.Println(r)


}

func main() {

	ring_sizes := [8]int{2, 128, 256, 512, 1024, 2048, 4096, 8192}

	for _, size := range ring_sizes{
		GetRunTime(size)
	}

}
