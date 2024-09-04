package util

import "math/rand/v2"

func FindRandom(min, max int) int {
	return rand.IntN(max-min) + min
}

func RandomSeed() int {
	return FindRandom(16, 32)
}
