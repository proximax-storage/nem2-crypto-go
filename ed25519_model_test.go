package crypto

import (
	"encoding/hex"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	message             = "NEM is awesome !"
	senderPrivateKey    = "2a91e1d5c110a8d0105aad4683f962c2a56663a3cad46666b16d243174673d90"
	recipientPrivateKey = "2618090794e9c9682f2ac6504369a2f4fb9fe7ee7746f9560aca228d355b1cb9"
	iv                  = "e1409b724bf6b591456a19ad4caa6932"
	salt                = "4ff36df9cbc91e740867c70b8787cf83b073949bbfb0e8e6d451fe32774dfe1f"
	encrypted           = "4ff36df9cbc91e740867c70b8787cf83b073949bbfb0e8e6d451fe32774dfe1fe1409b724bf6b591456a19ad4caa6932fcbf5c4898480f73082181d93f4f089b0e92de37c612e2c80c981874eb1be197"
)

type FakeReader struct {
	buf    []byte
	offset int
}

func (ref *FakeReader) Read(p []byte) (n int, err error) {
	if len(ref.buf)-ref.offset < len(p) {
		return 0, errors.New("not enough bytes in fake buffer")
	}

	for i, _ := range p {
		p[i] = ref.buf[ref.offset]
		ref.offset++
	}

	return len(p), nil
}

func NewFakeReader(bufs ...string) (*FakeReader, error) {
	b := make([]byte, 0)
	for _, buf := range bufs {
		eB, err := hex.DecodeString(buf)

		if err != nil {
			return nil, err
		}

		b = append(b, eB...)
	}

	reader := FakeReader{b, 0}
	return &reader, nil
}

func Test_Encrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	reader, err := NewFakeReader(salt, iv)
	assert.Nil(t, err)
	engine := Ed25519SeedCryptoEngine{reader}
	blockCipher := engine.CreateBlockCipher(senderkp, recipientkp)
	encodedMessage, err := blockCipher.Encrypt([]byte(message))
	assert.Nil(t, err)
	assert.Equal(t, encrypted, hex.EncodeToString(encodedMessage))
}

func Test_Decrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	blockCipher := NewBlockCipher(senderkp, recipientkp, nil)
	eB, err := hex.DecodeString(encrypted)
	assert.Nil(t, err)
	str, err := blockCipher.Decrypt(eB)
	assert.Nil(t, err)
	assert.Equal(t, message, string(str))
}

func Test_EncryptAndDecrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	blockCipherEncrypt := NewBlockCipher(senderkp, recipientkp, nil)
	blockCipherDecrypt := NewBlockCipher(senderkp, recipientkp, nil)
	encryptedData, err := blockCipherEncrypt.Encrypt([]byte(message))
	assert.Nil(t, err)
	decryptedData, err := blockCipherDecrypt.Decrypt(encryptedData)
	assert.Nil(t, err)
	assert.Equal(t, message, string(decryptedData))
}
