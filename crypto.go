// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
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

func EncodeMessageEd25519(senderPrivateKey *PrivateKey, recipientPublicKey *PublicKey, message string) (string, error) {

	sender, _ := NewKeyPair(senderPrivateKey, nil, nil)
	recipient, _ := NewKeyPair(nil, recipientPublicKey, nil)
	cipher := NewEd25519BlockCipher(sender, recipient, nil)
	payload := []byte(message)
	plainText, err := cipher.EncryptGCM(payload)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(plainText), nil
}

func DecodeMessageEd25519(recipientPrivateKey *PrivateKey, senderPublicKey *PublicKey, payload []byte) (string, error) {

	recipient, _ := NewKeyPair(recipientPrivateKey, nil, nil)
	sender, _ := NewKeyPair(nil, senderPublicKey, nil)
	cipher := NewEd25519BlockCipher(sender, recipient, nil)
	plainText, err := cipher.DecryptGCM(payload)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func EncodeMessageNaCl(senderPrivateKey *PrivateKey, recipientPublicKey *PublicKey, message string, salt []byte) (string, error) {

	var fsalt []byte
	if salt != nil {
		copy(fsalt, salt)
	} else {
		fsalt = make([]byte, 32)
	}
	encryptionKey := deriveSharedKey(senderPrivateKey.Raw, recipientPublicKey.Raw, fsalt)

	// Setup IV.
	ivData := MathUtils.GetRandomByteArray(12)

	// Encode.
	plainText := []byte(message)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	cipherText := mode.Seal(nil, ivData, plainText, nil)
	return hex.EncodeToString(cipherText[len(cipherText)-mode.Overhead():]) + hex.EncodeToString(ivData) + hex.EncodeToString(cipherText[:len(cipherText)-mode.Overhead()]), nil
}

func DecodeMessageNaCl(recipientPrivateKey *PrivateKey, senderPublicKey *PublicKey, payload []byte, salt []byte) (string, error) {
	var fsalt []byte
	if salt != nil {
		copy(fsalt, salt)
	} else {
		fsalt = make([]byte, 32)
	}
	encryptionKey := deriveSharedKey(recipientPrivateKey.Raw, senderPublicKey.Raw, fsalt)

	// Decode .

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ivData := payload[16:28]
	encTag := payload[0:16]
	cipherText := append(payload[28:], encTag...)

	decodedText, err := mode.Open(nil, ivData, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(decodedText), nil
}
func PrepareForScalarMult(sk []byte) []byte {
	hash, err := HashesSha3_512(sk)
	if err != nil {
		fmt.Println(err)
	}
	a := hash[:32]
	a[31] &= 0x7F
	a[31] |= 0x40
	a[0] &= 0xF8
	return a
}
func deriveSharedSecret(privateKey []byte, publicKey []byte) [32]byte {
	d := PrepareForScalarMult(privateKey)

	// sharedKey = pack(p = d (derived from privateKey) * q (derived from publicKey))
	q := [4][16]int64{gf(nil), gf(nil), gf(nil), gf(nil)}
	p := [4][16]int64{gf(nil), gf(nil), gf(nil), gf(nil)}
	sharedSecret := [32]byte{}
	var keyCopy [32]byte
	var d1 [32]byte
	copy(d1[:], d)
	copy(keyCopy[:], publicKey)
	unpack(&q, keyCopy)
	scalarmult(&p, &q, d1)
	pack(&sharedSecret, p)
	return sharedSecret
}

func deriveSharedKey(privateKey []byte, publicKey []byte, salt []byte) []byte {
	sharedSecret := deriveSharedSecret(privateKey, publicKey)
	// Underlying hash function for HMAC.
	hash := sha256.New

	// Non-secret salt, optional (can be nil).
	// Recommended: hash-length random value.

	// Non-secret context info, optional (can be nil).
	info := []byte("catapult")

	// Generate three 128-bit derived keys.
	hkdf := hkdf.New(hash, sharedSecret[:], salt, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
