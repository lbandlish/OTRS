package main

import (
	crand "crypto/rand"
	"encoding/binary"
	rand "math/rand"

	"fmt"
)


func randint64() (int64, error) {
	/*
	Use crypto rand to generate a random 64 bit number
	 */
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}

func PRG(seed int64) uint64{
	/*
	Use the given seed as a parameter to the PRG, output a pseudo random value
	 */
	rand.Seed(seed)
	randnum := rand.Uint64()
	return randnum
}

func GenKey() [128]uint64 {

return 0
}

func main() {
	seed, err :=randint64()
	random:=PRG(seed)

	fmt.Println(seed)
	if err != nil {
		panic(err)
	}
	fmt.Println(random)
}