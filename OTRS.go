package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"

)

import "golang.org/x/crypto/sha3"



//import "github.com/davidminor/uint128"



/*
func getbit(x uint128.Uint128, i int) uint8{
	if i<128 {
		fmt.Println(string(strconv.FormatUint(x.L, 2))[0])
		fmt.Println(strconv.FormatUint(x.L, 2)[0])

		return fmt.Sprintf("%b", x.L)[i]
	} else{
		return fmt.Sprintf("%b", x.L)[i-128]
	}
}
*/

func getbit(x uint64, i int) int{
	if fmt.Sprintf("%b", x)[i] == 48{
		return 0
	}	else {
		return 1
	}
}

func randint64() (uint64) {
	/*
	Use crypto rand to generate a random 64 bit number
	 */

	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}

func PRG(seed uint64) uint64{
	/*
	Use the given seed as a parameter to the PRG, output a pseudo random value
	 */

	rand.Seed(int64(seed))
	randnum := rand.Uint64()
	return randnum
}


func RSign(
	ring [][128]uint64,
	secret_key [128][2]uint64,
	l int,
	message string) ([]uint64, [][128]uint64){

	var r [][128]uint64
	var x []uint64
	var c [][128]uint64

	for i:=0; i< len(ring); i++ {
		var ri [128]uint64
		var ci [128]uint64
		x[i] = randint64()

		if i==l{
			for j:=0; j<128; j++{
				ci[i] = PRG(secret_key[j][0])
			}
		} else {
			for j:=0; j<128; j++{
				rij := randint64()
				prg_rij := PRG(rij)

				//bit at xi_j is 0
				if getbit(x[i], j) == 0{
					ci[j] = prg_rij
				} else {
					ci[j] = prg_rij ^ ring[i][j]
				}

				ri[j]=rij

			}

		}

		c[i] = ci
		r[i] = ri
	}

	h := make([]byte, 128)
	tohash := string(fmt.Sprintf("%v%v%v", ring, message, c))
	sha3.ShakeSum128(h, []byte(tohash))

	var xl uint64
	xl = 0

	for i:=0; i<128; i++{
		if i!=l{
			xl=x[i]^xl
		}
	}

	h2 := uint64(binary.LittleEndian.Uint64(h))
	x[l] = xl ^ h2

	for j:=0; j<128; j++{
		r[l][j] = secret_key[j][getbit(x[l],j)]
	}



	return x, r
}


func GenKey() ([128][2]uint64, [128]uint64) {
	var sk [128][2]uint64
	var pk [128]uint64

	for i := 0; i < 128; i++ {
		var s0 = randint64()
		var s1 = randint64()

		sk[i][0] = s0
		sk[i][1] = s1

		var pk0 = PRG(s0)
		var pk1 = PRG(s1)

		pk[i]= pk0^pk1

	}
	return sk, pk
}

func GenTestRing(size int, pk [128]uint64, position int) ([][128]uint64){
	var ring = make([][128]uint64, 0)

	for i:= 0; i<size; i++ {
		if i == position{
			ring = append(ring, pk)
		} else {
			var pkj [128]uint64
			for j :=0; j< 128; j++{
				var pk = uint64(randint64())
				pkj[j]=pk
			}
			ring =append(ring, pkj)

		}
	}
	return ring
}

func main() {


	var sk, pk = GenKey()
	fmt.Println(sk)
	fmt.Println(pk)

	var ring = GenTestRing(2, pk, 0)
	fmt.Println(ring)

	r, x := RSign(ring, sk, 0, "test")
	fmt.Println(r)
	fmt.Println(x)

}