// Package sm2 为国密SM2算法(椭圆曲线公钥密码算法)的Go语言实现（国标编号: GB/T 32918-2016，以下简称“国标”）
// 国标原文在线浏览: http://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=3EE2FD47B962578070541ED468497C5B
// 原创代码: https://github.com/ZZMarquis/gm
// 注释: paul_lee0919@163.com
// 使用许可: Apache License 2.0
package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"
	"sync"

	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/paul-lee-attorney/gm/util"
)

const (
	// BitSize 代表曲线基础域的比特长度
	BitSize = 256
	// KeyBytes 代表秘钥的字节长度，其中加7整除8其实是“向上取整”，用以兼容基础域位数不是8的整数倍的情况。
	KeyBytes = (BitSize + 7) / 8
	// UnCompress 代表椭圆曲线上的点采用“未压缩”的形式存储，占1个字节，详见国标1-4.1.(b)的定义。
	UnCompress = 0x04
)

// CipherTextType 是为了区分两个版本SM2国标在密文形式上的区别而创设的枚举类
type CipherTextType int32

const (
	//C1C2C3 代表旧标准[GM/T 0009-2012]的密文顺序
	C1C2C3 CipherTextType = 1
	//C1C3C2 代表新标准[GB/T 32918-2016]的密文顺序
	C1C3C2 CipherTextType = 2
)

var (
	// sm2H 代表SM2推荐曲线的余因子h,
	// 由于SM2推荐曲线的基域为素数域，所以h=1
	sm2H = new(big.Int).SetInt64(1)

	// sm2SignDefaultUserID 代表sm2算法默认的加密操作用户A的ID编码(详见国标5-A.1)和SM2使用规范(GB/T 35276-2017第10部分)
	sm2SignDefaultUserID = []byte{
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

// sm2P256V1 代表国密SM2推荐参数定义的椭圆曲线
var sm2P256V1 P256V1Curve

var initonce sync.Once

// P256V1Curve 代表国密SM2推荐参数定义的椭圆曲线:
// (1) 素数域256位椭圆曲线
// (2) 曲线方程为 Y^2 = X^3 + aX + b
// (3) 其他参数: p, a, b, n, Gx, Gy 详见国标SM2推荐曲线参数
// (4) 在GO语言标准库通用椭圆曲线参数类elliptic.CurveParams的基础上增加了参数a的属性
// (5) 由于SM2推荐曲线符合a=p-3, 所以上述曲线可简化为等价曲线 Y^2 = X^3 - 3X + b (mod p),
// 符合美标FIPS186-3预设的曲线函数，所以，可直接适用GO语言elliptic标准库的一些公共方法。
type P256V1Curve struct {
	*elliptic.CurveParams
	A *big.Int
}

// PublicKey 代表SM2算法的公钥类:
// (1) X,Y 为P点（有限素数域上基点G的D倍点)坐标
// (2) Curve 为SM2算法的椭圆曲线
type PublicKey struct {
	X, Y  *big.Int
	Curve P256V1Curve
}

// PrivateKey 代表SM2算法的私钥类:
// (1) D代表公钥P点相对于基点G的倍数
// (2) Curve 为SM2算法的椭圆曲线
type PrivateKey struct {
	D *big.Int
	PublicKey
	// Curve P256V1Curve
}

// sm2Signature 代表SM2算法的数字签名类。
type sm2Signature struct {
	R, S *big.Int
}

// sm2CiperC1C3C2 国密SM2算法新国标定义的密文类
type sm2CipherC1C3C2 struct {
	X, Y *big.Int
	C3   []byte
	C2   []byte
}

// sm2CiperC1C2C3 国密SM2算法旧国标定义的密文类
type sm2CipherC1C2C3 struct {
	X, Y *big.Int
	C2   []byte
	C3   []byte
}

// init 初始化国密SM2推荐参数计算得出的椭圆曲线。
func init() {
	initSm2P256V1()
}

// initSm2P256V1 为初始化国密SM2推荐参数计算得出的椭圆曲线:
// (1) 基域F(p)为素数域
// (2) 一次元x的系数a=p-3, 所以曲线方程等价于 y^2 = x^3 - 3x^2 + b (mod p) (即符合FIPS186-3标准预设函数)
// (3) 余因子h=1
func initSm2P256V1() {
	sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
	sm2P256V1.P = sm2P
	sm2P256V1.A = sm2A
	sm2P256V1.B = sm2B
	sm2P256V1.N = sm2N
	sm2P256V1.Gx = sm2Gx
	sm2P256V1.Gy = sm2Gy
	sm2P256V1.BitSize = BitSize
}

// GetSm2P256V1 为获取国密SM2椭圆曲线定义的函数。
func GetSm2P256V1() P256V1Curve {
	initonce.Do(initSm2P256V1)
	return sm2P256V1
}

// GenerateKey 为国密SM2生成秘钥对的函数:
// (1) 利用GO语言标准包crypto/rand生成随机数rand;
// (2) 将SM2推荐曲线参数和随机数rand输入GO语言标准包crypto/elliptic的公钥对生成方法GenerateKey()，生成密钥对核心参数(priv, x, y);
// (3) 根据PublicKey类和PrivateKey类的定义生成公钥和私钥的实例，并将上述核心参数赋值给实例各相应属性以完成初始化.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	priv, x, y, err := elliptic.GenerateKey(sm2P256V1, rand)
	if err != nil {
		return nil, err
	}
	privateKey := new(PrivateKey)
	privateKey.PublicKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(priv)
	// publicKey := new(PublicKey)
	// publicKey.Curve = sm2P256V1
	privateKey.PublicKey.X = x
	privateKey.PublicKey.Y = y
	return privateKey, nil
}

// RawBytesToPublicKey 将字节数组形式的原始格式数据转化为SM2公钥的方法:
// (1) 校验原始格式数据的字节长度(32的2倍,即64个字节)
// (2) 利用GO语言标准包math/big的SetBytes()方法将原始格式数据转变成大端整数
// (3) 赋值给PublicKey实例的相关属性，完成公钥初始化
func RawBytesToPublicKey(bytes []byte) (*PublicKey, error) {
	if len(bytes) != KeyBytes*2 {
		return nil, errors.New("Public key raw bytes length must be " + string(KeyBytes*2))
	}
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = new(big.Int).SetBytes(bytes[:KeyBytes])
	publicKey.Y = new(big.Int).SetBytes(bytes[KeyBytes:])
	return publicKey, nil
}

// RawBytesToPrivateKey 将字节数组形式的原始格式数据转变为SM2私钥的方法:
// (1) 校验原始格式数据的字节长度(256位除以8，即32字节)
// (2) 利用GO语言标准包math/big的SetBytes()方法将原始格式数据转变成大端整数
// (3) 赋值给PrivateKey实例的相关属性，完成私钥初始化
func RawBytesToPrivateKey(bytes []byte) (*PrivateKey, error) {
	if len(bytes) != KeyBytes {
		return nil, errors.New("Private key raw bytes length must be " + string(KeyBytes))
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(bytes)
	return privateKey, nil
}

// GetUnCompressBytes 为获取未压缩字节数组格式存储的公钥的方法:
// (1) 将PublicKey实例的坐标(x,y)分别转化为字节数组
// (2) 将“未压缩”标识"0x04"写入输出字节数组raw[]的首字节raw[0]
// (3) 将x坐标写入raw[:33], 将y坐标写入raw[33:]
func (pub *PublicKey) GetUnCompressBytes() []byte {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

// GetRawBytes 为获得字节数组格式存储的公钥的方法(不带“未压缩”标识字节)。
func (pub *PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}

// GetRawBytes 为获得字节数组格式存储的私钥的方法。
func (pri *PrivateKey) GetRawBytes() []byte {
	dBytes := pri.D.Bytes()
	dl := len(dBytes)
	if dl > KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw, dBytes[dl-KeyBytes:])
		return raw
	} else if dl < KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw[KeyBytes-dl:], dBytes)
		return raw
	} else {
		return dBytes
	}
}

// CalculatePubKey 为SM2利用私钥推算公钥的方法:
// (1) 创设公钥实例，将私钥携带的曲线赋值给公钥实例
// (2) 利用GO语言标准包(crypto/elliptic)定义的Curve接口的ScalarBaseMult()方法，
// 根据椭圆曲线、基点G、私钥(D倍数)推算公钥(倍点P)
func CalculatePubKey(priv *PrivateKey) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = priv.Curve
	pub.X, pub.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())
	return pub
}

// nextK 为生成[1, max)范围内随机整数的函数:
// (1) 利用标准库math/big设置整数1
// (2) 利用标准库crypto/rand生成随机数
// (3) 审核随机数范围[1, max)
// (4) 本算法中max为基础域的阶数n
func nextK(rnd io.Reader, max *big.Int) (*big.Int, error) {
	intOne := new(big.Int).SetInt64(1)
	var k *big.Int
	var err error
	for {
		k, err = rand.Int(rnd, max)
		if err != nil {
			return nil, err
		}
		if k.Cmp(intOne) >= 0 {
			return k, err
		}
	}
}

// xor 函数是将国标3-6.1.A5和3-6.1.A6两步结合到一起的异或函数,
// 其计算结果返回调用来源函数kdf(),
// 从而可在计算中间变量t的同时异或、拼接获得C2:
// (1) data 为输入明文消息M
// (2) kdfOut[] 为秘钥派生函数输出缓存buf[]
// (3) dRemaining 为KDF()函数中标注输入消息数组encData[]每次调用xor()时，
// 阶段性“读”动作读取的字节数组元素个数
func xor(data []byte, kdfOut []byte, dRemaining int) {
	for i := 0; i != dRemaining; i++ {
		data[i] ^= kdfOut[i]
	}
}

// kdf 为SM2公钥加密算法中调用秘钥派生函数的操作步骤（国标4-6.1.A5）:
// (1) 按照哈希摘要字节长度创设缓存切片buf[]
// (2) 以公钥P的k倍点坐标(c1x, c1y)和输入明文消息M(长度为klen位)为输入参数
// (3) 按照国标4-5.4.3定义的秘钥派生函KDF()和国标第4-6.1.A5规定的算法推算中间变量t
// (4) t=KDF(c1x||c1y, klen), 该算法核心是迭代调用Hash(c1x||c1y||ct)，其中:
//     (a) ct为32位整数计数器, 从1起算
//     (b) 调用次数为klen/v向上取整次
//     (c) v代表哈希摘要的位数长度(SM3为256位)
//     (d) 最后一次调用若明文M剩余长度小于v, 则取有值的字节
// (5) C2=M^t, 即通过xor()在计算中间变量t的过程中将中间结果与M的对应字节进行异或运算
func kdf(digest hash.Hash, c1x *big.Int, c1y *big.Int, encData []byte) {
	// 4个字节为32位字长
	bufSize := 4
	if bufSize < digest.Size() {
		// SM3哈希算法的摘要长度为32字节(256位)，所以，此处取值将为32
		bufSize = digest.Size()
	}
	buf := make([]byte, bufSize)

	// 输入消息的字节数组长度，根据国标第2部分5.4.3定义，其值应小于(2^32-1)*v
	// 鉴于SM3的哈希值长度v为256位，所以，klen应当小于(2^32-1)*2^8
	encDataLen := len(encData)

	// 加密算法中，(c1x, c1y)为公钥P的k倍点(k为加密过程中产生随机整数)
	c1xBytes := c1x.Bytes()
	c1yBytes := c1y.Bytes()

	// encData[]元素序号“读”指针
	off := 0
	// 32位计数器
	ct := uint32(0)
	for off < encDataLen {
		digest.Reset()
		digest.Write(c1xBytes)
		digest.Write(c1yBytes)
		ct++
		binary.BigEndian.PutUint32(buf, ct)
		//ct为32位计数器，占4个字节，所以Write()方法仅需要读取到buf[:4]
		digest.Write(buf[:4])

		// 循环写入哈希值H(c1x || c2y || ct)到缓存数组buf[]
		tmp := digest.Sum(nil)
		copy(buf[:bufSize], tmp[:bufSize])

		xorLen := encDataLen - off
		if xorLen > digest.Size() {
			xorLen = digest.Size()
		}
		xor(encData[off:], buf, xorLen)
		off += xorLen
	}
}

// notEncrypted 为国标3-6.1.A5中判断中间变量t是否为全0比特串的判断函数。
// 如果C2与输入消息M每个字节都相等，就意味着在3-6.1.A6进行异或计算(C2=M^t)时，中间变量t所有字节均为0。
// 此时，应当重新选择随机数k，重启加密计算流程。
func notEncrypted(encData []byte, in []byte) bool {
	encDataLen := len(encData)
	for i := 0; i != encDataLen; i++ {
		if encData[i] != in[i] {
			return false
		}
	}
	return true
}

// Encrypt 为SM2加密函数:
// (1) 输入参数为: 公钥PB点(pub.X, pub.Y), 明文消息字节数组 in[], 密文类别标识 cipherTextType
// (2) 生成随机数k, k属于区间[1,N-1]
// (3) 利用标准包elliptic的方法CurveParams.ScalarBaseMult()生成倍点C1=kG=(c1x, c1y)
// (4) 由于SM2推荐曲线为素数域椭圆曲线，其余因子h=1，此时，点S=[h]PB就是公钥PB点，不可能为无穷远点O，
// 所以，国标4-6.1.A3被省略
// (5) 利用标准包elliptic的方法CurveParams.ScalarBaseMult()生成倍点kPB=(kPBx, kPBy)
// (6) 调用改进后的秘钥派生函数kdf(), 生成C2
func Encrypt(pub *PublicKey, in []byte, cipherTextType CipherTextType) ([]byte, error) {
	c2 := make([]byte, len(in))
	copy(c2, in)
	var c1 []byte
	digest := sm3.New()
	var kPBx, kPBy *big.Int
	for {
		// 利用标准库crypto/rand获取随机数k
		k, err := nextK(rand.Reader, pub.Curve.N)
		if err != nil {
			return nil, err
		}
		kBytes := k.Bytes()
		// 利用标准库elliptic的方法CurveParams.ScalarBaseMult()计算倍点C1=kG=(c1x, c1y)
		c1x, c1y := pub.Curve.ScalarBaseMult(kBytes)

		// 将公钥曲线与C1点的坐标参数序列化。
		c1 = elliptic.Marshal(pub.Curve, c1x, c1y)

		// 利用标准库elliptic的方法CurveParams.ScalarMult()计算倍点kPB=(kPBx, kPBy)
		kPBx, kPBy = pub.Curve.ScalarMult(pub.X, pub.Y, kBytes)

		// 利用改造后的秘钥派生函数推算C2
		kdf(digest, kPBx, kPBy, c2)

		// 若中间变量t全部字节均为0则重启加密运算(详见国标4-6.1.A5)
		if !notEncrypted(c2, in) {
			break
		}
	}

	// 推算C3=Hash(kPBx || M || kPBy)，详见国标4-6.1.A7
	digest.Reset()
	digest.Write(kPBx.Bytes())
	digest.Write(in)
	digest.Write(kPBy.Bytes())
	c3 := digest.Sum(nil)

	// 根据密文格式标识的选择输出密文(C1C3C2新国准，或C1C2C3旧国标)
	c1Len := len(c1)
	c2Len := len(c2)
	c3Len := len(c3)
	result := make([]byte, c1Len+c2Len+c3Len)
	if cipherTextType == C1C2C3 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c2Len], c2)
		copy(result[c1Len+c2Len:], c3)
	} else if cipherTextType == C1C3C2 {
		copy(result[:c1Len], c1)
		copy(result[c1Len:c1Len+c3Len], c3)
		copy(result[c1Len+c3Len:], c2)
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
	return result, nil
}

// Decrypt 为SM2算法利用私钥解密(国标4-7.1)的函数:
// (1) 读取C1
// (2) 反序列化同时校验C1点是否位于私钥曲线上
// (3) 校验S点(S=[h]C1)是否为无穷远点O
// (4) 私钥推算倍点[d]C1
// (5) 采用改造后的kdf()函数，计算并获取解密后的明文消息M'=C2^t
// (6) 计算u=Hash(c1x || M' || c2y)并与C3诸位比较
// (7) 返回解密后的明文消息M'
func Decrypt(priv *PrivateKey, in []byte, cipherTextType CipherTextType) ([]byte, error) {
	// 根据算法字长读取C1
	c1Len := ((priv.Curve.BitSize+7)/8)*2 + 1
	c1 := make([]byte, c1Len)
	copy(c1, in[:c1Len])

	// 读取C1点坐标(c1x, c1y)，并校验是否位于曲线上(标准库方法elliptic.Unmarshal()内部调用)
	c1x, c1y := elliptic.Unmarshal(priv.Curve, c1)

	// 校验S点是否为无穷远点(在素数域上h为1，S点即为C1点, 本步骤可忽略)
	sx, sy := priv.Curve.ScalarMult(c1x, c1y, sm2H.Bytes())
	if util.IsEcPointInfinity(sx, sy) {
		return nil, errors.New("[h]C1 at infinity")
	}

	// 根据私钥(priv.D)和曲线计算倍点[priv.D]C1=(c1x, c1y)
	c1x, c1y = priv.Curve.ScalarMult(c1x, c1y, priv.D.Bytes())

	// 根据密文格式，分别读取C2和C3
	digest := sm3.New()
	c3Len := digest.Size()
	c2Len := len(in) - c1Len - c3Len
	c2 := make([]byte, c2Len)
	c3 := make([]byte, c3Len)
	if cipherTextType == C1C2C3 {
		copy(c2, in[c1Len:c1Len+c2Len])
		copy(c3, in[c1Len+c2Len:])
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[c1Len:c1Len+c3Len])
		copy(c2, in[c1Len+c3Len:])
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}

	// 采用改造后的kdf()函数，计算并获取解密后的明文消息M'=C2^t(国标4-7.1.B4-B5)
	kdf(digest, c1x, c1y, c2)

	// 计算u=Hash(c1x || M' || c2y)(国标4-7.1.B6-1)
	digest.Reset()
	digest.Write(c1x.Bytes())
	digest.Write(c2)
	digest.Write(c1y.Bytes())
	newC3 := digest.Sum(nil)

	// 将u与C3逐位比较(国标4-7.1.B6-2)
	if !bytes.Equal(newC3, c3) {
		return nil, errors.New("invalid cipher text")
	}

	// 返回明文消息M'
	return c2, nil
}

// MarshalCipher 为SM2算法密文对象序列化公共函数:
// (1) 将字节数组中保存的SM2密文对象截取出来
// (2) 将截取出来的数据赋值给SM2密文对象的各相关属性
// (3) 将SM2密文对象序列化为符合ASN.1标准DER编码规则的密文字节串
// (4) SM2密文对象的具体规范请见国标(GB/T 35276-2017)
func MarshalCipher(in []byte, cipherTextType CipherTextType) ([]byte, error) {
	// 将椭圆曲线的位数转化为字节数
	byteLen := (sm2P256V1.Params().BitSize + 7) >> 3
	c1x := make([]byte, byteLen)
	c1y := make([]byte, byteLen)

	// 将in[]按C1,C2,C3长度进行拆分
	c2Len := len(in) - (1 + byteLen*2) - sm3.Size
	c2 := make([]byte, c2Len)
	c3 := make([]byte, sm3.Size)
	pos := 1

	// 拆分获取c1x, c1y
	copy(c1x, in[pos:pos+byteLen])
	pos += byteLen
	copy(c1y, in[pos:pos+byteLen])
	pos += byteLen
	nc1x := new(big.Int).SetBytes(c1x)
	nc1y := new(big.Int).SetBytes(c1y)

	// 根据新旧国标的格式标识拆分C2和C3
	if cipherTextType == C1C2C3 {
		copy(c2, in[pos:pos+c2Len])
		pos += c2Len
		copy(c3, in[pos:pos+sm3.Size])
		result, err := asn1.Marshal(sm2CipherC1C2C3{nc1x, nc1y, c2, c3})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else if cipherTextType == C1C3C2 {
		copy(c3, in[pos:pos+sm3.Size])
		pos += sm3.Size
		copy(c2, in[pos:pos+c2Len])
		result, err := asn1.Marshal(sm2CipherC1C3C2{nc1x, nc1y, c3, c2})
		if err != nil {
			return nil, err
		}
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

// UnmarshalCipher 为SM2算法密文对象反序列化公共函数:
// (1) 将符合ASN.1标准DER编码规则的密文字节串反序列化为SM2密文对象
// (2) 将SM2密文对象的各相关属性的值读出来并按规范存入字节数组
// (3) SM2密文对象的具体规范请见国标(GB/T 35276-2017)
func UnmarshalCipher(in []byte, cipherTextType CipherTextType) (out []byte, err error) {
	if cipherTextType == C1C2C3 {
		cipher := new(sm2CipherC1C2C3)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1x := cipher.X.Bytes()
		c1y := cipher.Y.Bytes()
		c1xLen := len(c1x)
		c1yLen := len(c1y)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1x)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1y)
		pos += c1yLen
		copy(result[pos:pos+c2Len], cipher.C2)
		pos += c2Len
		copy(result[pos:pos+c3Len], cipher.C3)
		return result, nil
	} else if cipherTextType == C1C3C2 {
		cipher := new(sm2CipherC1C3C2)
		_, err = asn1.Unmarshal(in, cipher)
		if err != nil {
			return nil, err
		}
		c1x := cipher.X.Bytes()
		c1y := cipher.Y.Bytes()
		c1xLen := len(c1x)
		c1yLen := len(c1y)
		c2Len := len(cipher.C2)
		c3Len := len(cipher.C3)
		result := make([]byte, 1+c1xLen+c1yLen+c2Len+c3Len)
		pos := 0
		result[pos] = UnCompress
		pos += 1
		copy(result[pos:pos+c1xLen], c1x)
		pos += c1xLen
		copy(result[pos:pos+c1yLen], c1y)
		pos += c1yLen
		copy(result[pos:pos+c3Len], cipher.C3)
		pos += c3Len
		copy(result[pos:pos+c2Len], cipher.C2)
		return result, nil
	} else {
		return nil, errors.New("unknown cipherTextType:" + string(cipherTextType))
	}
}

// getZ 为SM2签名算法的第1步预处理函数，即，以签名方身份标识和公钥信息为基础获取Z值:
// (1) 首2个字节存储用户ID的比特长度ENTL
// (2) 之后存储用户ID的字节串
// (3) 之后顺次存储a, b, XG, YG四个椭圆曲线定义参数
// (4) 之后顺次存储签名方公钥PA点的坐标XA和YA
// (5) 输入参数的接口类hash.Hash，将由SM3算法具体实现，详见调用来源
// (6) 具体算法见国标2-5.5
func getZ(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userID []byte) []byte {
	digest.Reset()

	userIDLen := uint16(len(userID) * 8)
	var userIDLenBytes [2]byte
	binary.BigEndian.PutUint16(userIDLenBytes[:], userIDLen)
	digest.Write(userIDLenBytes[:])
	if userID != nil && len(userID) > 0 {
		digest.Write(userID)
	}

	digest.Write(curve.A.Bytes())
	digest.Write(curve.B.Bytes())
	digest.Write(curve.Gx.Bytes())
	digest.Write(curve.Gy.Bytes())
	digest.Write(pubX.Bytes())
	digest.Write(pubY.Bytes())
	return digest.Sum(nil)
}

// calculateE 为SM2签名算法的第2步预处理函数，即，以Z值和带签名消息为基础获取哈希值H:
// (1) 将第1步预处理获得的Z值写入SM3哈希函数
// (2) 将拟签名消息M写入SM3哈希函数
// (3) 获取哈希值H
// (4) 输入参数的接口类hash.Hash，将由SM3算法具体实现，详见调用来源
// (5) 具体算法见国标2-6.1
func calculateE(digest hash.Hash, curve *P256V1Curve, pubX *big.Int, pubY *big.Int, userID []byte, src []byte) *big.Int {
	z := getZ(digest, curve, pubX, pubY, userID)

	digest.Reset()
	digest.Write(z)
	digest.Write(src)
	eHash := digest.Sum(nil)
	return new(big.Int).SetBytes(eHash)
}

// MarshalSign 为SM2将签名对象(r, s)序列化函数，即将签名对象序列化为符合ASN.1标准DER编码规则的字节串。
func MarshalSign(r, s *big.Int) ([]byte, error) {
	result, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UnmarshalSign 为SM2将签名对象反序列化函数，即将符合ASN.1标准DER编码规则的字节串反序列化为SM2签名对象。
func UnmarshalSign(sign []byte) (r, s *big.Int, err error) {
	sm2Sign := new(sm2Signature)
	_, err = asn1.Unmarshal(sign, sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}

// SignToRS 为SM2签名算法的核心函数:
// (1) 以私钥(d倍数)为基础推算公钥点PA(XA, YA)
// (2) 调用预处理函数获取H值
// (3) 调用标准包crypto/rand获取随机数k (国标2-6.1.A3)
// (4) 推算曲线点(x1, y1) = [k]G (国标2-6.1.A4)
// (5) 调用标准包math/big封装的加和取模函数计算r = (e + x1) mod n,
// 并校验r<>0, 且r+k<>n (国标2-6.1.A5)
// (6) 调用标准包math/big封装的取乘法逆元和取模函数计算s = ((1+d)^(-1) * (k - rd)) mod n,
// 并校验s <> 0 (国标2-6.1.A6)
// (7) 返回计算结果(r, s)
func SignToRS(priv *PrivateKey, userID []byte, in []byte) (r, s *big.Int, err error) {
	digest := sm3.New()
	pubX, pubY := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	if userID == nil {
		userID = sm2SignDefaultUserID
	}
	e := calculateE(digest, &priv.Curve, pubX, pubY, userID, in)

	intZero := new(big.Int).SetInt64(0)
	intOne := new(big.Int).SetInt64(1)
	for {
		var k *big.Int
		var err error
		for {
			k, err = nextK(rand.Reader, priv.Curve.N)
			if err != nil {
				return nil, nil, err
			}
			px, _ := priv.Curve.ScalarBaseMult(k.Bytes())
			r = util.Add(e, px)
			r = util.Mod(r, priv.Curve.N)

			rk := new(big.Int).Set(r)
			rk = rk.Add(rk, k)
			if r.Cmp(intZero) != 0 && rk.Cmp(priv.Curve.N) != 0 {
				break
			}
		}

		dPlus1ModN := util.Add(priv.D, intOne)
		dPlus1ModN = util.ModInverse(dPlus1ModN, priv.Curve.N)
		s = util.Mul(r, priv.D)
		s = util.Sub(k, s)
		s = util.Mod(s, priv.Curve.N)
		s = util.Mul(dPlus1ModN, s)
		s = util.Mod(s, priv.Curve.N)

		if s.Cmp(intZero) != 0 {
			break
		}
	}

	return r, s, nil
}

// Sign 为封装后的SM2签名算法公共函数:
// (1) 输入参数为: 签名用户的私钥、ID和待签名信息
// (2) 调用SignToRS函数推算签名结果(r,s)
// (3) 调用MarshalSign函数将签名对象序列化为符合ASN.1标准DER编码规则的字节数组
func Sign(priv *PrivateKey, userID []byte, in []byte) ([]byte, error) {
	r, s, err := SignToRS(priv, userID, in)
	if err != nil {
		return nil, err
	}

	return MarshalSign(r, s)
}

// VerifyByRS 为SM2验证签名算法的核心函数，输入参数为消息来源方公钥、用户ID、原始消息:
// (1) 调用math/big标准包（以下略）校验 1 <= r' < n (国标2-7.1.B1)
// (2) 校验 1 <= s' < n (国标2-7.1.B1)
// (3) 调用预处理函数，制备e' = Hash (Z||M') (国标2-7.1.B3-B4)
// (4) 计算 t = (r' + s') mod n, 并校验t<>0 (国标2-7.1.B5)
// (5) 调用elliptic标准包计算曲线上点(x1', y1') = [s']G + [t]PA, 并校验是否为无穷远点O(其实没必要) (国标2-7.1.B5)
// (6) 计算R = (e' + x1') mod n
// (7) 若 R = r' 则通过校验
func VerifyByRS(pub *PublicKey, userID []byte, src []byte, r, s *big.Int) bool {
	intOne := new(big.Int).SetInt64(1)
	if r.Cmp(intOne) == -1 || r.Cmp(pub.Curve.N) >= 0 {
		return false
	}
	if s.Cmp(intOne) == -1 || s.Cmp(pub.Curve.N) >= 0 {
		return false
	}

	digest := sm3.New()
	if userID == nil {
		userID = sm2SignDefaultUserID
	}
	e := calculateE(digest, &pub.Curve, pub.X, pub.Y, userID, src)

	intZero := new(big.Int).SetInt64(0)
	t := util.Add(r, s)
	t = util.Mod(t, pub.Curve.N)
	if t.Cmp(intZero) == 0 {
		return false
	}

	sgx, sgy := pub.Curve.ScalarBaseMult(s.Bytes())
	tpx, tpy := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := pub.Curve.Add(sgx, sgy, tpx, tpy)
	if util.IsEcPointInfinity(x, y) {
		return false
	}

	expectedR := util.Add(e, x)
	expectedR = util.Mod(expectedR, pub.Curve.N)
	return expectedR.Cmp(r) == 0
}

// Verify 为SM2封装后的签名验证函数,
// 输入参数为签名人的公钥、ID、原始消息和DER编码字节数组形式的签名(r, s),
// 反序列化签名后调用核心算法函数VerifyByRS校验签名。
func Verify(pub *PublicKey, userID []byte, src []byte, sign []byte) bool {
	r, s, err := UnmarshalSign(sign)
	if err != nil {
		return false
	}

	return VerifyByRS(pub, userID, src, r, s)
}
