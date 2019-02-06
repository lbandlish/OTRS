package main

import (
	crand "crypto/rand"
	"encoding/binary"
	rand "math/rand"
	"strconv"

	"fmt"
)

import "github.com/davidminor/uint128"
import "github.com/golang-collections/go-datastructures/bitarray"




func getbit(x uint128.Uint128, i int) uint8{
	if i<128 {
		fmt.Println(string(strconv.FormatUint(x.L, 2))[0])
		fmt.Println(strconv.FormatUint(x.L, 2)[0])

		return fmt.Sprintf("%b", x.L)[i]
	} else{
		return fmt.Sprintf("%b", x.L)[i-128]
	}
}


func randint64() (int64) {
	/*
	Use crypto rand to generate a random 64 bit number
	 */

	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

func PRG(seed int64) uint64{
	/*
	Use the given seed as a parameter to the PRG, output a pseudo random value
	 */

	rand.Seed(seed)
	randnum := rand.Uint64()
	return randnum
}


func GenKey() ([128][2]int64, [128]uint64) {
	var sk [128][2]int64
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
	var s0 = uint64(randint64())
	var s1 = uint64(randint64())

	keything := uint128.Uint128{H: s0, L: s1}
	fmt.Println(getbit(keything,2))

	/*var sk, pk = GenKey()
	fmt.Println(sk)
	fmt.Println(pk)

	var ring = GenTestRing(2, pk, 0)
	fmt.Println(ring)*/

}