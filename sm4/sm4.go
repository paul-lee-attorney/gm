// Package sm4 为国密SM4算法(分组密码算法)的Go语言实现（推荐性国标编号: GB/T 32907-2016）
// 国家标准在线浏览: http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=7803DE42D3BC5E80B0C3E5D8E873D56A
// 原创代码: https://github.com/ZZMarquis/gm
// 注释: paul_lee0919@163.com
// 使用许可: Apache License 2.0
package sm4

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"strconv"
)

const (
	// BlockSize 代表以“字节”为单位核算的分组长度，折算成“比特”则为128位。
	BlockSize = 16
	// KeySize 代表以“字节”为单位核算的秘钥长度，折算成“比特”则为128位。
	KeySize = 16
)

// sBox 代表规定的二维表Sbox（详见国标6.2部分的表1）的一维展开数组。
var sBox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

// cK 为SM4国标规定的固定参数（详见国标7.3.(c)部分）。
var cK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// fK 为SM4国标规定的系统参数（详见国标7.3.(b)部分）。
var fK = [4]uint32{
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
}

// KeySizeError 代表长度不正确的初始秘钥类
type KeySizeError int

// Error 方法返回错误提示信息。
func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// sm4Cipher 为SM4的密文结构体。
type sm4Cipher struct {
	enc []uint32
	dec []uint32
}

// NewCipher 创设SM4密文类的实例并初始化。
func NewCipher(key []byte) (cipher.Block, error) {
	n := len(key)
	if n != KeySize {
		return nil, KeySizeError(n)
	}
	c := new(sm4Cipher)
	c.enc = expandKey(key, true)
	c.dec = expandKey(key, false)
	return c, nil
}

// BlockSize 返回SM4算法的分组长度。
func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

// Encrypt() 为SM4的加密方法函数。
// (1) 校验输入消息字节数组的长度
// (2) 校验输出消息字节数组的长度
// (3) 调用分组处理函数processBlock()
func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	processBlock(c.enc, src, dst)
}

// Decrypt() 为SM4的加密方法函数。
// (1) 校验输入消息字节数组的长度
// (2) 校验输出消息字节数组的长度
// (3) 调用分组处理函数processBlock()
func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	processBlock(c.dec, src, dst)
}

// expandKey 为SM4国标(7.3)定义的秘钥扩展算法函数。
// (1) 将加密秘钥key拆分成mK[i], (i=0,1,2,3) (详见国密7.3公式(6))
// (2) 将mK[i]与系统参数fK[i]进行异或运算获得x[i], (i=0, 1, 2, 3)
// (3) 调用轮秘钥生成函encRound()或decRound()迭代生成轮秘钥rk[i], (i=0, 1, ... 31)
func expandKey(key []byte, forEnc bool) []uint32 {
	var mK [4]uint32
	mK[0] = binary.BigEndian.Uint32(key[0:4])
	mK[1] = binary.BigEndian.Uint32(key[4:8])
	mK[2] = binary.BigEndian.Uint32(key[8:12])
	mK[3] = binary.BigEndian.Uint32(key[12:16])

	var x [5]uint32
	x[0] = mK[0] ^ fK[0]
	x[1] = mK[1] ^ fK[1]
	x[2] = mK[2] ^ fK[2]
	x[3] = mK[3] ^ fK[3]

	var rk [32]uint32
	if forEnc {
		for i := 0; i < 32; i++ {
			x[(i+4)%5] = encRound(x[i%5], x[(i+1)%5], x[(i+2)%5], x[(i+3)%5], x[(i+4)%5], rk[:], i)
		}
	} else {
		for i := 0; i < 32; i++ {
			x[(i+4)%5] = decRound(x[i%5], x[(i+1)%5], x[(i+2)%5], x[(i+3)%5], x[(i+4)%5], rk[:], i)
		}
	}
	return rk[:]
}

// tau() 为国标(6.2.(a))规定的Sbox非线性变换τ(.)，其中：
// (1) 如果将Sbox二维表逐行展开为一维数组s[]，则数组元素的序号就是Sbox行序号乘16加列序号；
// (2) 因为Sbox二维表本身为16x16的表，而1个字节存储单元能够存储8位二进制数，折算16进制就是2位16进制数;
// (3) 所以，若将1个字节所表示的二进制数字a，折算成16进制数字（假设为EF），然后将其高位E作为行坐标、将低位F作为列坐标，
//     则数字a就可以用来表示Sbox二维表中某个元素的行列坐标(E,F):
// (4) Sbox二维表中，坐标为(E,F)的元素展开成数组s[]后，其数组序号就是: Ex16 + F，这其实就是数字a的值;
// (5) 所以，根据非线性变换τ(.)的定义，Sbox(a)=s[a]
func tau(a uint32) uint32 {
	var aArr [4]byte
	var bArr [4]byte
	binary.BigEndian.PutUint32(aArr[:], a)
	bArr[0] = sBox[aArr[0]]
	bArr[1] = sBox[aArr[1]]
	bArr[2] = sBox[aArr[2]]
	bArr[3] = sBox[aArr[3]]
	return binary.BigEndian.Uint32(bArr[:])
}

// lAp 为国标(7.3.(a))定义的线性变换函数L'()
func lAp(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

// tAp 为国标(7.3)定义的合成转置函数T'()
func tAp(z uint32) uint32 {
	return lAp(tau(z))
}

// encRound 为加密轮秘钥扩展算法。
func encRound(x0 uint32, x1 uint32, x2 uint32, x3 uint32, x4 uint32, rk []uint32, i int) uint32 {
	x4 = x0 ^ tAp(x1^x2^x3^cK[i])
	rk[i] = x4
	return x4
}

// decRound 为解密轮秘钥扩展算法。
func decRound(x0 uint32, x1 uint32, x2 uint32, x3 uint32, x4 uint32, rk []uint32, i int) uint32 {
	x4 = x0 ^ tAp(x1^x2^x3^cK[i])
	rk[31-i] = x4
	return x4
}

// processBlock 为SM4核心算法函数:
// (1) 将in[]数组存储的输入消息(128位)按4个字节为1个“字”(32位)来分组，划分成4组；
// (2) 结合轮秘钥rk，根据国标(7.1.(a))规定，按轮函数F算法进行32轮迭代加密；
// (3) 根据国标(7.1.(b))规定，进行反序变换;
// (4) 将推算结果写入out[]数组。
func processBlock(rk []uint32, in []byte, out []byte) {
	var x [BlockSize / 4]uint32
	x[0] = binary.BigEndian.Uint32(in[0:4])
	x[1] = binary.BigEndian.Uint32(in[4:8])
	x[2] = binary.BigEndian.Uint32(in[8:12])
	x[3] = binary.BigEndian.Uint32(in[12:16])

	for i := 0; i < 32; i += 4 {
		x[0] = f0(x[:], rk[i])
		x[1] = f1(x[:], rk[i+1])
		x[2] = f2(x[:], rk[i+2])
		x[3] = f3(x[:], rk[i+3])
	}
	r(x[:])

	binary.BigEndian.PutUint32(out[0:4], x[0])
	binary.BigEndian.PutUint32(out[4:8], x[1])
	binary.BigEndian.PutUint32(out[8:12], x[2])
	binary.BigEndian.PutUint32(out[12:16], x[3])
}

// l() 为国标(6.2.(b))规定的合成置换函数T(.)的第二步骤：线性变换函数L()。
func l(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
		bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

// t() 为国标(6.2)规定的合成置换函数T(.)
func t(z uint32) uint32 {
	return l(tau(z))
}

// r() 为国标(7.1.(b))定义的反序变换函数:
// (1) 两个二进制数A0和B0, 初次异或运算结果为A1, 则A1=A0^B0;
// (2) A1与B0进行第二次异或运算结果为B1，则B1=A1^B0=A0^B0^B0=A0;
// (3) A1与B1进行第三次异或运算结果为A2，则A2=A1^B1=A0^B0^A0=B0;
// (4) 若A、B均为变量，将A0/A1/A2均用变量A存储，B0/B1均用变量B存储，则
//     上述计算可简述为：三次异或运算交换变量值。
func r(a []uint32) {
	a[0] = a[0] ^ a[3]
	a[3] = a[0] ^ a[3]
	a[0] = a[0] ^ a[3]
	a[1] = a[1] ^ a[2]
	a[2] = a[1] ^ a[2]
	a[1] = a[1] ^ a[2]
}

// f0() 代表国标(6.1和7.1.(a))定义的轮函数F()，在i=0时对应的实例。
func f0(x []uint32, rk uint32) uint32 {
	return x[0] ^ t(x[1]^x[2]^x[3]^rk)
}

// f0() 代表国标(6.1和7.1.(a))定义的轮函数F()，在i=1时对应的实例。
func f1(x []uint32, rk uint32) uint32 {
	return x[1] ^ t(x[2]^x[3]^x[0]^rk)
}

// f0() 代表国标(6.1和7.1.(a))定义的轮函数F()，在i=2时对应的实例。
func f2(x []uint32, rk uint32) uint32 {
	return x[2] ^ t(x[3]^x[0]^x[1]^rk)
}

// f0() 代表国标(6.1和7.1.(a))定义的轮函数F()，在i=3时对应的实例。
func f3(x []uint32, rk uint32) uint32 {
	return x[3] ^ t(x[0]^x[1]^x[2]^rk)
}
