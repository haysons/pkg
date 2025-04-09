package utils

import (
	"encoding/binary"
	"fmt"
	"github.com/dchest/siphash"
	"github.com/google/uuid"
	"github.com/rs/xid"
	"time"
)

// UUID 生成 google v4 uuid，36字符
func UUID() string {
	return uuid.NewString()
}

// UUIDHex 生成 google v4 uuid, 并使用16进制编码，32字符
func UUIDHex() string {
	uidBytes, _ := uuid.New().MarshalBinary()
	return HexEncode(uidBytes)
}

// UUIDBase32 生成 google v4 uuid, 并使用base32编码，26字符
func UUIDBase32() string {
	uidBytes, _ := uuid.New().MarshalBinary()
	return Base32Encode(uidBytes)
}

// UUIDBase58 生成 google v4 uuid，并使用base58编码，22字符
func UUIDBase58() string {
	uidBytes, _ := uuid.New().MarshalBinary()
	return Base58Encode(uidBytes)
}

// XID 生成xid，xid相较于uuid占用空间更少，20字符，生成速度更快，但基于时间自增，可被推测，存在一定的安全问题
func XID() string {
	return xid.New().String()
}

// NumericUID 基于唯一值（如自增主键）得到整型的uid，默认uid范围位于闭区间100_000_000至999_999_999之间
func NumericUID(id uint64) uint64 {
	return numericUIDGenerator.Generate(id)
}

// NumericUIDNano 基于纳秒级时间戳生成整型uid，默认uid范围为位于闭区间100_000_000至999_999_999之间
func NumericUIDNano() uint64 {
	nano := time.Now().UnixNano()
	return numericUIDGenerator.Generate(uint64(nano))
}

var numericUIDGenerator *NumericUIDGenerator

func init() {
	numericUIDGenerator, _ = NewNumericUIDGenerator(100_000_000, 999_999_999, 193764502379472, 546271840266420)
}

// NumericUIDGenerator 整形uid生成器
type NumericUIDGenerator struct {
	minUID    uint64
	maxUID    uint64
	rangeSize uint64
	key1      uint64
	key2      uint64
}

func NewNumericUIDGenerator(min, max, key1, key2 uint64) (*NumericUIDGenerator, error) {
	if min > max {
		return nil, fmt.Errorf("invalid range [%d, %d]", min, max)
	}
	return &NumericUIDGenerator{
		minUID:    min,
		maxUID:    max,
		rangeSize: max - min + 1,
		key1:      key1,
		key2:      key2,
	}, nil
}

// Generate 基于唯一id生成数字uid，数字uid范围位于闭区间[minUID, maxUID]之间
func (g *NumericUIDGenerator) Generate(ID uint64) uint64 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], ID)
	hashed := siphash.Hash(g.key1, g.key2, buf[:])
	return (hashed % g.rangeSize) + g.minUID
}
