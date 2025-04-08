package utils

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAESEncryptAndDecrypt(t *testing.T) {
	plaintext := []byte("This is a test message for AES-GCM encryption.")
	key := []byte("12345678901234567890123456789012") // 32 bytes key for AES-256

	ciphertext, err := AESEncrypt(plaintext, key)
	assert.NoError(t, err, "AESEncrypt should not return an error")

	decryptedText, err := AESDecrypt(ciphertext, key)
	assert.NoError(t, err, "AESDecrypt should not return an error")

	assert.True(t, bytes.Equal(plaintext, decryptedText), "Decrypted text should be the same as the original plaintext")
}

func TestAESDecryptInvalidCiphertext(t *testing.T) {
	invalidCiphertext := []byte("invalidciphertext")

	_, err := AESDecrypt(invalidCiphertext, []byte("12345678901234567890123456789012"))
	assert.Error(t, err, "AESDecrypt should return an error for invalid ciphertext")
}

func TestAESDecryptWithWrongKey(t *testing.T) {
	plaintext := []byte("This is a test message for AES-GCM encryption.")
	key := []byte("12345678901234567890123456789012")
	ciphertext, err := AESEncrypt(plaintext, key)
	assert.NoError(t, err, "AESEncrypt should not return an error")

	wrongKey := []byte("wrongkey123456789012345678901234")
	_, err = AESDecrypt(ciphertext, wrongKey)
	assert.Error(t, err, "AESDecrypt should return an error for incorrect key")
}

func TestAESDecryptWithShortCiphertext(t *testing.T) {
	invalidCiphertext := []byte("short")

	_, err := AESDecrypt(invalidCiphertext, []byte("12345678901234567890123456789012"))
	assert.Error(t, err, "AESDecrypt should return an error for ciphertext that is too short")
}

func TestGenerateRSAKeyPair(t *testing.T) {
	_, _, err := GenerateRSAKeyPair(1024)
	assert.Error(t, err, "Should fail for key size less than 2048 bits")

	priv, pub, err := GenerateRSAKeyPair(2048)
	assert.NoError(t, err, "Key generation should succeed for 2048 bits")
	assert.NotNil(t, priv, "Private key should not be nil")
	assert.NotNil(t, pub, "Public key should not be nil")
}

func TestPEMEncodeDecode(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	assert.NoError(t, err)

	pubPEM, err := PublicKeyToPEM(pub)
	assert.NoError(t, err)
	assert.NotEmpty(t, pubPEM, "PublicKey PEM should not be empty")

	decodedPub, err := PEMToPublicKey(pubPEM)
	assert.NoError(t, err)
	assert.Equal(t, pub.E, decodedPub.E, "Decoded public key exponent must match")
	assert.Equal(t, pub.N, decodedPub.N, "Decoded public key modulus must match")

	privPEM, err := PrivateKeyToPEM(priv)
	assert.NoError(t, err)
	assert.NotEmpty(t, privPEM, "PrivateKey PEM should not be empty")

	decodedPriv, err := PEMToPrivateKey(privPEM)
	assert.NoError(t, err)
	assert.Equal(t, priv.PublicKey.E, decodedPriv.PublicKey.E, "Decoded private key public exponent must match")
	assert.Equal(t, priv.PublicKey.N, decodedPriv.PublicKey.N, "Decoded private key modulus must match")
}

func TestRSAEncryptDecrypt(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	assert.NoError(t, err)

	plaintext := []byte("This is a test message for RSA-OAEP encryption.")

	ciphertext, err := RSAEncrypt(plaintext, pub)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext, "Ciphertext should not be empty")

	decryptedText, err := RSADecrypt(ciphertext, priv)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, decryptedText), "Decrypted text should match the original plaintext")
}

func TestRSASignVerify(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	assert.NoError(t, err)

	data := []byte("This is a test message for RSA-PSS signing.")

	signature, err := RSASign(data, priv)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature, "Signature should not be empty")

	err = RSAVerify(data, signature, pub)
	assert.NoError(t, err, "Signature verification should succeed")

	modifiedData := []byte("This is a modified message for RSA-PSS signing.")
	err = RSAVerify(modifiedData, signature, pub)
	assert.Error(t, err, "Signature verification should fail for modified data")
}

func TestPEMDecodeFailures(t *testing.T) {
	invalidPubPEM := []byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----")
	_, err := PEMToPublicKey(invalidPubPEM)
	assert.Error(t, err, "PEMToPublicKey should error on invalid PEM data")

	invalidPrivPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----")
	_, err = PEMToPrivateKey(invalidPrivPEM)
	assert.Error(t, err, "PEMToPrivateKey should error on invalid PEM data")

	_, err = PEMToPublicKey([]byte{})
	assert.Error(t, err, "Empty PEM should return error for public key")
	_, err = PEMToPrivateKey([]byte{})
	assert.Error(t, err, "Empty PEM should return error for private key")
}

func TestHMACSignAndVerify(t *testing.T) {
	key := []byte("my-secret-key")
	message := []byte("important-message")

	signature := HMACSign(message, key)
	assert.NotEmpty(t, signature, "HMAC signature should not be empty")

	valid := HMACVerify(message, signature, key)
	assert.True(t, valid, "HMAC verification should succeed with correct key and message")

	wrongKey := []byte("wrong-key")
	valid = HMACVerify(message, signature, wrongKey)
	assert.False(t, valid, "HMAC verification should fail with incorrect key")

	wrongMessage := []byte("tampered-message")
	valid = HMACVerify(wrongMessage, signature, key)
	assert.False(t, valid, "HMAC verification should fail with tampered message")

	// Empty key and message
	var emptyKey []byte
	var emptyMessage []byte
	emptySig := HMACSign(emptyMessage, emptyKey)
	assert.True(t, HMACVerify(emptyMessage, emptySig, emptyKey), "HMAC should work with empty message and key")
}
