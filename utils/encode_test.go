package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHexEncodeDecode(t *testing.T) {
	original := []byte("hello world")
	encoded := HexEncode(original)
	decoded, err := HexDecode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestBase32EncodeDecode(t *testing.T) {
	original := []byte("hello world")
	encoded := Base32Encode(original)
	decoded, err := Base32Decode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestBase64EncodeDecode(t *testing.T) {
	original := []byte("hello world")
	encoded := Base64Encode(original)
	decoded, err := Base64Decode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestBase58EncodeDecode(t *testing.T) {
	original := []byte("hello world")
	encoded := Base58Encode(original)
	decoded, err := Base58Decode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestUint32EncodeDecode(t *testing.T) {
	values := []uint32{0, 1, 12345, 4294967295}

	for _, v := range values {
		encoded := Uint32Encode(v)
		assert.Len(t, encoded, 4, "Encoded uint32 should be 4 bytes")
		decoded := Uint32Decode(encoded)
		assert.Equal(t, v, decoded, "Decoded value should match original")
	}
}

func TestUint64EncodeDecode(t *testing.T) {
	values := []uint64{0, 1, 1234567890, 18446744073709551615}

	for _, v := range values {
		encoded := Uint64Encode(v)
		assert.Len(t, encoded, 8, "Encoded uint64 should be 8 bytes")
		decoded := Uint64Decode(encoded)
		assert.Equal(t, v, decoded, "Decoded value should match original")
	}
}

type TestStruct struct {
	Name string
	Age  int
}

func TestMsgpackMarshalUnmarshal(t *testing.T) {
	data := TestStruct{Name: "Alice", Age: 30}
	bytes, err := MsgpackMarshal(data)
	assert.NoError(t, err)

	var decoded TestStruct
	err = MsgpackUnmarshal(bytes, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestSanitizeEncodeDecode(t *testing.T) {
	data := TestStruct{Name: "Bob", Age: 42}
	encoded, err := SanitizeEncode(data)
	assert.NoError(t, err)

	var decoded TestStruct
	err = SanitizeDecode(encoded, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestSanitizeCustomEncoder(t *testing.T) {
	encoder := NewSanitizeEncoder("Lxv9frHdiqRPuzoG2MV7BmKCyFQN1ZjwApt3Eg4WDUkJY5behs8SanXT6c")
	data := map[string]interface{}{"score": 99, "pass": true}

	encoded, err := encoder.Encode(data)
	assert.NoError(t, err)

	var decoded map[string]interface{}
	err = encoder.Decode(encoded, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, data["score"], int(decoded["score"].(int8))) // msgpack returns int8
	assert.Equal(t, data["pass"], decoded["pass"])
}
