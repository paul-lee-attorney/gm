// Package sm3 为国密SM3算法的Go语言实现（推荐性国标编号: GB/T 32905-2016）
// 原创代码: https://github.com/ZZMarquis/gm
// 注释: paul_lee0919@163.com
// 所适用的软件使用许可: Apache License 2.0
package sm3

import (
	"encoding/binary"
	"fmt"
	"hash"
	"math/bits"
)

const (
	// Size 代表SM3哈希摘要以“字节”为计量单位核算的长度。
	Size = 32
	// BlockSize 代表迭代压缩前，输入消息分组时，长度相等的分组数据块以“字节”为计量单位核算的长度。
	BlockSize = 64
)

// gT 为SM3国密算法中的常量T(j)随下标j变化而进行左移j位运算（详见国标5.3.3获取中间变量SS1的算法）的计算结果数组，其中:
// (1) (0 <= j <= 15)时, T(j) = 0x79CC4519
// (2) (16 <= j <= 63)时, T(j) = 0x7A879D8A
// (3) 左移j位和左移(j mod 32)位的运算结果相同
// (4) 具体实现的算法见函数PrintT()
var gT = []uint32{
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
	0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

// digest 为SM3算法哈希摘要类，属于私有类，仅SM3包内可以调用
type digest struct {
	v            [Size / 4]uint32      // v[8] 为迭代压缩运算结果的8个“字”寄存器，其存储值为中间运算结果或最终哈希值。
	inWords      [BlockSize / 4]uint32 // inWords[16] 为输入消息分组数据块（512位）再次拆分所形成的16个输入消息“字”数组，是后续扩展消息、迭代压缩运算的数据基础。
	endOfInWords int32                 // endOfInWords 代表持续写入输入消息时，inWords[]数组非空元素的尾部序号指针。
	w            [68]uint32            // w[68] 代表迭代压缩过程中的消息扩展“字”数组。
	inBuf        [4]byte               // inBuf[4] 为以“字节”为单位暂存输入消息的缓存数组，其目的旨在将输入消息凑够一个“字”的长度，即4个字节。
	endOfInBuf   int32                 // endOfInBuf 为inBuff[]数组非空元素的尾部序号指针。
	lenInBytes   int64                 // lenInBytes 为输入消息以“字节”为单位的长度，在“填充”过程中将折算成以“比特”为单位的长度。
}

// New 创建digest的实例，并根据国标（GB/T 32905-2016）规定的初始值（IV）初始化寄存器保存的值。
func New() hash.Hash {
	digest := new(digest)
	digest.Reset()
	return digest
}

// Sum 为GO语言hash标准接口类中Sum()方法的实现。
// 其功能是将输入消息与其哈希值连接在一个字节数组中，
// 方便数字指纹核实、数字签名等应用中同时获得输入消息和其哈希值。
func (digest *digest) Sum(b []byte) []byte {
	d1 := digest
	h := d1.checkSum()
	return append(b, h[:]...)
}

// Size 方法返回SM3哈希摘要以字节为计量单位核算的长度。
// 为GO语言hash标准接口类中规定的Size()方法的实现。
func (digest *digest) Size() int {
	return Size
}

// BlockSize 是为了提高运算效率，给开发者提供的一个查询算法消息分组数据长度的接口。
// 尽管哈希算法可将任意长度的消息进行哈希运算，但如果输入消息的长度为分组数据块长度的整数倍，
// 则可以大大提高运算效率，降低运算次数。
// 返回的是单位消息分组以“字节”为单位核算的消息长度，与GO语言标准包SHA256的口径保持一致。
func (digest *digest) BlockSize() int {
	return BlockSize
}

// Reset 为初始化或重置哈希摘要的方法。
// v[] 的首次赋值为国标规定的初始值IV。
func (digest *digest) Reset() {
	digest.lenInBytes = 0

	digest.endOfInBuf = 0
	for i := 0; i < len(digest.inBuf); i++ {
		digest.inBuf[i] = 0
	}

	for i := 0; i < len(digest.inWords); i++ {
		digest.inWords[i] = 0
	}

	for i := 0; i < len(digest.w); i++ {
		digest.w[i] = 0
	}

	digest.v[0] = 0x7380166F
	digest.v[1] = 0x4914B2B9
	digest.v[2] = 0x172442D7
	digest.v[3] = 0xDA8A0600
	digest.v[4] = 0xA96F30BC
	digest.v[5] = 0x163138AA
	digest.v[6] = 0xE38DEE4D
	digest.v[7] = 0xB0FB0E4E

	digest.endOfInWords = 0
}

// Write() 为哈希摘要的“写”方法，是GO语言hash类的标准接口方法，为公共方法，可外部调用。
// 其功能旨在将输入消息按照SM3国标规定的分组、迭代、压缩函数整理写入8个字寄存器。
// 鉴于输入消息写入时可能为多次、持续的过程，所以，Write()方法并没有将“填充”步骤考虑在内，
// 而是将“填充”步骤放到最后，在收尾函数finish()方法中再实现输入消息的“填充”步骤。
func (digest *digest) Write(p []byte) (n int, err error) {
	_ = p[0] // 若写入消息为nil，直接产生panic
	inLen := len(p)

	i := 0
	// endOfInBuf 不为0，代表着前一次写操作，存在不能凑成“字”（4个字节）的尾部数据。
	if digest.endOfInBuf != 0 {
		for i < inLen {
			digest.inBuf[digest.endOfInBuf] = p[i]
			digest.endOfInBuf++
			i++
			if digest.endOfInBuf == 4 {
				digest.processWord(digest.inBuf[:], 0)
				digest.endOfInBuf = 0
				break
			}
		}
	}

	// &^3相当于将本数X的尾部2位清零，相当于X减去其对4取模的余数，结果将获得小于等于本数X的最大的4的倍数
	limit := ((inLen - i) & ^3) + i
	// i 以4为单位累加循环，将输入消息写入inWords[]
	for ; i < limit; i += 4 {
		digest.processWord(p, int32(i))
	}

	// 将输入消息的尾部信息写入寄存数组inBuf[]
	for i < inLen {
		digest.inBuf[digest.endOfInBuf] = p[i]
		digest.endOfInBuf++
		i++
	}

	// 累加输入消息的字节长度到lenInBytes
	digest.lenInBytes += int64(inLen)

	// 返回本次写操作的字节长度
	n = inLen
	return
}

// finish() 为SM3算法的收尾方法:
// (1) 确认输入消息已经完全写入，并计算输入消息的长度;
// (2) 根据输入消息的长度，完成尾部数据的“填充”操作;
// (3) 将填充完毕的尾部数据进行分组、迭代和压缩运算。
func (digest *digest) finish() {

	// 左移3位，相当于左边数字乘以2的3次幂（即乘以8），实质上是将字节数折算成比特“位”数。
	bitLength := digest.lenInBytes << 3

	// 首位为“1”其余位为“0”的字节，为输入消息结束后“填充”操作的第一个步骤，即在消息末尾填充比特“1”。
	digest.Write([]byte{128})

	// 若存在不能凑成“字”的零散尾部数据，则填充“0”字节，凑成完整的“字”。
	for digest.endOfInBuf != 0 {
		digest.Write([]byte{0})
	}

	// 调用processLength()方法, 完成“填充”步骤，制作成最后的长度为512位整数倍的数据分组。
	digest.processLength(bitLength)

	// 调用processBlock()方法, 就“填充”完成后的尾部数据，进行国标5.3部分的迭代、压缩运算。
	digest.processBlock()
}

// checkSum() 为SM3获取哈希值的结果输出函数:
// (1) 调用收尾方法finish()，完成输入消息尾部的填充、迭代和压缩；
// (2) 以32位的“字”为单位，将哈希值写入输出数组out[];
// (3) 返回输出字节数组out[]。
func (digest *digest) checkSum() [Size]byte {
	digest.finish()
	vlen := len(digest.v)
	var out [Size]byte
	for i := 0; i < vlen; i++ {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], digest.v[i])
	}
	return out
}

// processBlock() 为分组数据块的处理函数，是SM3算法的核心：
// (1) 将输入消息的16个“字”数组，按照国标5.3.2(a)的算法拆分并赋值给消息扩展数组w[0]-w[15]；
// (2) 按照国标5.3.2(b)部分规定的算法，制备w[16]-w[67];
// (3) 将v[0]-v[7]的哈希运算中间结果赋值给8个“字”寄存器ABCDEFGH;
// (4) 将国标5.3.2(c)部分规定的w'[]的推导算法，和5.3.3部分规定的迭代压缩算法相结合，完成迭代压缩运算;
// (5) 将寄存器ABCDEFGH中保存的迭代运算结果与v[0]-v[7]中保存的中间结果“异或运算”后存入v[]。
func (digest *digest) processBlock() {
	for j := 0; j < 16; j++ {
		digest.w[j] = digest.inWords[j]
	}
	for j := 16; j < 68; j++ {
		wj3 := digest.w[j-3]
		r15 := (wj3 << 15) | (wj3 >> (32 - 15))
		wj13 := digest.w[j-13]
		r7 := (wj13 << 7) | (wj13 >> (32 - 7))
		digest.w[j] = p1(digest.w[j-16]^digest.w[j-9]^r15) ^ r7 ^ digest.w[j-6]
	}

	A := digest.v[0]
	B := digest.v[1]
	C := digest.v[2]
	D := digest.v[3]
	E := digest.v[4]
	F := digest.v[5]
	G := digest.v[6]
	H := digest.v[7]

	for j := 0; j < 16; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := digest.w[j]
		W1j := Wj ^ digest.w[j+4] // 国标5.3.2(c)部分规定的w'[]的推导算法
		TT1 := ff0(A, B, C) + D + SS2 + W1j
		TT2 := gg0(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	for j := 16; j < 64; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := digest.w[j]
		W1j := Wj ^ digest.w[j+4] // 国标5.3.2(c)部分规定的w'[]的推导算法
		TT1 := ff1(A, B, C) + D + SS2 + W1j
		TT2 := gg1(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	digest.v[0] ^= A
	digest.v[1] ^= B
	digest.v[2] ^= C
	digest.v[3] ^= D
	digest.v[4] ^= E
	digest.v[5] ^= F
	digest.v[6] ^= G
	digest.v[7] ^= H

	digest.endOfInWords = 0
}

// processWord() 为写入过程中凑“字”长的方法：
// (1) 将输入的字节数据，以4字节位单位，写入inWords[];
// (2) 每当写入消息字长达到16个字，即512字节，则调用一次processBlock()方法.
func (digest *digest) processWord(in []byte, inOff int32) {
	n := binary.BigEndian.Uint32(in[inOff : inOff+4])

	digest.inWords[digest.endOfInWords] = n
	digest.endOfInWords++

	// 每达到16个字，调用一次分组数据块处理方法processBlock();
	if digest.endOfInWords >= 16 {
		digest.processBlock()
	}
}

// processLength() SM3算法“填充”步骤的实现函数。
func (digest *digest) processLength(bitLength int64) {
	// 若仅剩余一个“字”的空位，则直接填充“0”、调用分组数据块处理方法。
	if digest.endOfInWords > (BlockSize/4 - 2) {
		digest.inWords[digest.endOfInWords] = 0
		digest.endOfInWords++

		digest.processBlock()
	}

	// 填充“0”占位，只剩余64位留给存储输入消息长度。
	for ; digest.endOfInWords < (BlockSize/4 - 2); digest.endOfInWords++ {
		digest.inWords[digest.endOfInWords] = 0
	}

	// 将64位整数表示的输入消息长度，拆分成两个32位“字”，分别将高位和地位存储到两个inWords[]数组元素中
	digest.inWords[digest.endOfInWords] = uint32(bitLength >> 32)
	digest.endOfInWords++
	digest.inWords[digest.endOfInWords] = uint32(bitLength)
	digest.endOfInWords++
}

// p0() 为国标4.4条规定的置换函数。
// 直接引入GO语言标准库bits.RotateLeft32()方法。
func p0(x uint32) uint32 {
	r9 := bits.RotateLeft32(x, 9)
	r17 := bits.RotateLeft32(x, 17)
	return x ^ r9 ^ r17
}

// p1() 为国标4.4条规定的置换函数。
// 直接引入GO语言标准库bits.RotateLeft32()方法。
func p1(x uint32) uint32 {
	r15 := bits.RotateLeft32(x, 15)
	r23 := bits.RotateLeft32(x, 23)
	return x ^ r15 ^ r23
}

// ff0() 为国标4.3条规定的(0 <= j <= 15)条件下的布尔函数FF(j)。
func ff0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

// ff1() 为国标4.3条规定的(16 <= j <= 63)条件下的布尔函数FF(j)。
func ff1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// gg0() 为国标4.3条规定的(0 <= j <= 15)条件下的布尔函数GG(j)。
func gg0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

// gg1() 为国标4.3条规定的(16 <= j <= 63)条件下的布尔函数GG(j)。
func gg1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

// Sum 为SM3一步生成输入消息data[]哈希值的函数，属公共函数，可直接在包外调用。
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

// PrintT 为SM3生成T(j)常数左移j位的结果数组的算法函数，可直接在包外调用。
func PrintT() {
	var T [64]uint32
	fmt.Print("{")
	for j := 0; j < 16; j++ {
		T[j] = 0x79CC4519
		Tj := (T[j] << uint32(j)) | (T[j] >> (32 - uint32(j)))
		fmt.Printf("0x%08X, ", Tj)
	}

	for j := 16; j < 64; j++ {
		n := j % 32
		T[j] = 0x7A879D8A
		Tj := (T[j] << uint32(n)) | (T[j] >> (32 - uint32(n)))
		if j == 63 {
			fmt.Printf("0x%08X}\n", Tj)
		} else {
			fmt.Printf("0x%08X, ", Tj)
		}
	}
}
