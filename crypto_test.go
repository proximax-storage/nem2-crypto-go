package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashesSha_256(t *testing.T) {
	const proof = "36e82fd88dbd06c07effe09ac6a652aca2b111b653d05429df494ad958273098"

	secretB, err := HashesSha_256([]byte(proof))
	assert.Nil(t, err)

	assert.Equal(t, "c346f5ecf5bcfa54ab14fad815c8239bdeb051df8835d212dba2af59f688a00e", hex.EncodeToString(secretB))
}

func TestHashesKeccak_256(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesKeccak_256(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "241c1d54c18c8422def03aa16b4b243a8ba491374295a1a6965545e6ac1af314", hex.EncodeToString(secretB))
}

func TestHashesSha3_256(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesSha3_256(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "9b3155b37159da50aa52d5967c509b410f5a36a3b1e31ecb5ac76675d79b4a5e", hex.EncodeToString(secretB))
}

func TestHashesSha3_512(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7680ADA57" +
		"DCEC8EEE91C4E3BF3BFA9AF6FFDE90CD1D249D1C6121D7B759A001B1"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesSha3_512(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "d23859866f93f2698a5b48586543c608d85a57c74e9ce92d86a0b25065d"+
		"8155c16754d840026b8c536f2bcb963a7d867f034ec241b87162ac33daf7b707cb5f7", hex.EncodeToString(secretB))
}

func TestHashesRipemd160(t *testing.T) {
	const proof = "8ed368fe7077da578f72785771529a407d3c40e70fff0f70723a34d8d1a643ce"

	secretB, err := HashesRipemd160([]byte(proof))
	assert.Nil(t, err)

	assert.Equal(t, "3fc43d717d824302e3821de8129ea2f7786912e5", hex.EncodeToString(secretB))
}

func TestEncryptDecryptGCMDefault(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	startMessage := "This is a random test message that must match forever and ever."
	encoded, err := EncodeMessageEd25519(sender.PrivateKey, recipient.PublicKey, startMessage)
	assert.Nil(t, err)
	decodedStr, err := hex.DecodeString(encoded)
	assert.Nil(t, err)
	decoded, err := DecodeMessageEd25519(recipient.PrivateKey, sender.PublicKey, decodedStr)
	assert.Nil(t, err)
	assert.Equal(t, startMessage, decoded)
}

func TestEncryptDecryptGCMNaCl(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	startMessage := "This is a random test message that must match forever and ever. Now adding messages to use more than one block :D. This is a random test message that must match forever and ever. This is a random test message that must match forever and ever. This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever."
	encoded, err := EncodeMessageNaCl(sender.PrivateKey, recipient.PublicKey, startMessage, nil)
	assert.Nil(t, err)
	decodedStr, err := hex.DecodeString(encoded)
	assert.Nil(t, err)
	decoded, err := DecodeMessageNaCl(recipient.PrivateKey, sender.PublicKey, decodedStr, nil)
	assert.Nil(t, err)
	assert.Equal(t, startMessage, decoded)
}
func TestDerivedKeyCompatNaCl(t *testing.T) {
	sender, _ := NewRandomKeyPair()
	recipient, _ := NewRandomKeyPair()
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw, salt)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw, salt)
	fmt.Printf("%x,%x", sharedKey, sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}

func TestDerivedKeyCompatNaClMany(t *testing.T) {
	for i := 0; i < 20; i++ {
		sender, err := NewRandomKeyPair()
		assert.Nil(t, err)
		recipient, err := NewRandomKeyPair()
		assert.Nil(t, err)
		salt := make([]byte, 32) //zeroed salt
		sharedKey := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw, salt)
		sharedKey2 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw, salt)
		assert.Equal(t, sharedKey, sharedKey2)
	}

}

func TestDerivedKeyCompatNaClFixed(t *testing.T) {
	key, err := NewPrivateKeyfromHexString("2F985E4EC55D60C957C973BD1BEE2C0B3BA313A841D3EE4C74810805E6936053")
	assert.Nil(t, err)
	key2, err := NewPrivateKeyfromHexString("D6430327F90FAAD41F4BC69E51EB6C9D4C78B618D0A4B616478BD05E7A480950")
	assert.Nil(t, err)
	sender, err := NewKeyPair(key, nil, nil)
	assert.Nil(t, err)
	recipient, _ := NewKeyPair(key2, nil, nil)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw, salt)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw, salt)
	fmt.Printf("%x,%x", sharedKey, sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}
func TestDerivedKeyCompatNaClExpected(t *testing.T) {
	key, err := NewPublicKeyfromHex("9952DB28FF8186DD45F11A0BCD72872729D42098C03BE024FC3E7D5BC2BE40F1")
	assert.Nil(t, err)
	key2, err := NewPrivateKeyfromHexString("D6430327F90FAAD41F4BC69E51EB6C9D4C78B618D0A4B616478BD05E7A480950")
	assert.Nil(t, err)
	recipient, _ := NewKeyPair(key2, nil, nil)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(recipient.PrivateKey.Raw, key.Raw, salt)
	fmt.Printf("%x", sharedKey)
	expected, err := hex.DecodeString("5410B86B33D5AE3519633A8C0686B8109163F337B2948C1C8A91AE7FE9FAE37C")
	assert.Nil(t, err)
	assert.Equal(t, sharedKey, expected)
}

func TestDerivedKeyCompatDefault(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	cipher := NewEd25519BlockCipher(sender, recipient, nil)
	sharedKey, err := cipher.GetSharedKey(sender.PrivateKey, recipient.PublicKey, salt)
	assert.Nil(t, err)
	sharedKey2, err := cipher.GetSharedKey(recipient.PrivateKey, sender.PublicKey, salt)
	assert.Nil(t, err)
	assert.Equal(t, sharedKey, sharedKey2)
}

func TestDerivedKeyCompatNaClMatchesEd25519Impl(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	cipher := NewEd25519BlockCipher(sender, recipient, nil)
	sharedKey, err := cipher.GetSharedKey(sender.PrivateKey, recipient.PublicKey, salt)
	assert.Nil(t, err)
	sharedKey2, err := cipher.GetSharedKey(recipient.PrivateKey, sender.PublicKey, salt)
	assert.Nil(t, err)
	sharedKey3 := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw, salt)
	sharedKey4 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw, salt)
	fmt.Printf("%x,%x\n%x,%x", sharedKey, sharedKey2, sharedKey3, sharedKey4)
	assert.Equal(t, sharedKey, sharedKey2)
	assert.Equal(t, sharedKey3, sharedKey4)
	assert.Equal(t, sharedKey, sharedKey3)

}
