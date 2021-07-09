// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// HashesSha_256 return Sha 256 hash of byte
func HashesSha_256(b []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesKeccak_256 return Keccak 256 hash of byte
func HashesKeccak_256(b []byte) ([]byte, error) {
	hash := sha3.NewLegacyKeccak256()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesSha3_256 return sha3 256 hash of byte
func HashesSha3_256(b []byte) ([]byte, error) {
	hash := sha3.New256()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesSha3_512 return sha3 512 hash of byte
func HashesSha3_512(inputs ...[]byte) ([]byte, error) {
	hash := sha3.New512()
	for _, b := range inputs {

		_, err := hash.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return hash.Sum(nil), nil
}

// HashesRipemd160  return ripemd160 hash of byte
func HashesRipemd160(b []byte) ([]byte, error) {
	hash := ripemd160.New()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil

}

func isNegativeConstantTime(b int) int {
	return (b >> 8) & 1
}

func isConstantTimeByteEq(b, c int) int {

	result := 0
	xor := b ^ c // final
	for i := uint(0); i < 8; i++ {
		result |= xor >> i
	}

	return (result ^ 0x01) & 0x01
}

func isEqualConstantTime(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

func Clamp(d *[]byte) {
	(*d)[0] &= 248
	(*d)[31] &= 127
	(*d)[31] |= 64
}
func PrepareForScalarMult(sk []byte) []byte {
	d := []byte{}
	hash := sha512.Sum512_256(sk)
	n := copy(d[0:32], hash[:])
	if n != 32 {
		panic("Invalid checksum copy!")
	}
	Clamp(&d)
	return d
}
func deriveSharedSecret(privateKey []byte, publicKey []byte) [32]byte {
	d := PrepareForScalarMult(privateKey)
	// sharedKey = pack(p = d (derived from privateKey) * q (derived from publicKey))
	q := [4][128]byte{gf(nil), gf(nil), gf(nil), gf(nil)}
	p := [4][128]byte{gf(nil), gf(nil), gf(nil), gf(nil)}
	sharedSecret := [32]byte{}
	var keyCopy [32]byte
	var d1 [32]byte
	copy(d1[:], d)
	copy(keyCopy[:], publicKey)
	unpack(&q, keyCopy)
	scalarmult(&p, &q, &d1)
	pack(&sharedSecret, p)
	return sharedSecret
}

func deriveSharedKey(privateKey []byte, publicKey []byte) []byte {
	sharedSecret := deriveSharedSecret(privateKey, publicKey)
	// Underlying hash function for HMAC.
	hash := sha256.New

	// Non-secret salt, optional (can be nil).
	// Recommended: hash-length random value.
	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// Non-secret context info, optional (can be nil).
	info := []byte("catapult")

	// Generate three 128-bit derived keys.
	hkdf := hkdf.New(hash, sharedSecret[:], salt, info)

	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
