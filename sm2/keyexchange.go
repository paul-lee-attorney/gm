package sm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/paul-lee-attorney/gm/util"
)

/*
	国标(GMT 0003.3-2012, 以下简称“国标”) 规定的SM2算法秘钥交换协议
*/

// ExchangeResult 为国标规定的最后推导出的秘钥交换协议的结果:
// Key 为共享秘钥，比如SM4秘钥
// S1 为校验B用户ID的可选中间参数，其哈希函数输入参数的头部为0x02
// S2 为校验A用户ID的可选中间参数，其哈希函数输入参数的头部为0x03
type ExchangeResult struct {
	Key []byte
	S1  []byte
	S2  []byte
}

// reduce 为国密算法中获取(x拔)的中间函数, 详见国标6.1的A4/A6和B3/B5，其中:
// 1. Lsh() 为左位移方法，将整数1左移w位，相当于获取2^w
// 2. SetBit(x, i, b) 为设定整数x第i位为b的函数，当b为1时，相当于x | (1<<i)
// 3. x拔在国标中的定义为: 2^w + (x & (2^w - 1)), 其中:
// (1) 2^w二进制表示为w位为1，后续其他位均为0，因此
// (2) 若A = 2^w - 1， 则计算结果A的第w位的值必定为0，因此
// (2) 若B = x & A， 则与运算结果B的第w位也必定为0， 因此
// (3) SetBit (reulst, w, 1) 相当于result + 2^w
// 综上，reduce的计算结果就是 (x拔) =  2^w + (x & (2^w - 1))
func reduce(x *big.Int, w int) *big.Int {
	intOne := new(big.Int).SetInt64(1)
	result := util.Lsh(intOne, uint(w))
	result = util.Sub(result, intOne)
	result = util.And(x, result)
	result = util.SetBit(result, w, 1)
	return result
}

// calculateU 为推导共享秘钥(曲线上关键点U)的函数，其中:
// x1 为己方临时公钥点R1的x值所对应的x拔: x1 =  2^w + (x1 & (2^w - 1))
// x2 为对方临时公钥点R2的x值所对应的x拔: x2 = 2^w + (x2 & (2^w - 1))
// tA 为己方临时私钥r1乘x1加永久私钥d1，之后对基点阶数n取模所得的tA = (d1 + x1.r1) mod n
// sm2H 为SM2曲线余因子h, 应当为曲线点个数#E(Fq)除以基点G阶数n的商，对SM2推荐曲线而言，h=1
// 关键点U = h*tA*(P2 + x2*R2) = h*tA*P2 + h*tA*x2*R2 = k1*P2 + k2*R2
// 值得注意的是，取模计算被从tA计算，挪到了k1和k2步骤，从取模运算的乘法交换律来看，结果并没有影响，
// 但可以尽量让k2模运算后的结果更小，进而降低后续步骤的运算压力。
func calculateU(w int, selfStaticPriv *PrivateKey, selfEphemeralPriv *PrivateKey, selfEphemeralPub *PublicKey,
	otherStaticPub *PublicKey, otherEphemeralPub *PublicKey) (x *big.Int, y *big.Int) {
	x1 := reduce(selfEphemeralPub.X, w)
	x2 := reduce(otherEphemeralPub.X, w)
	tA := util.Mul(x1, selfEphemeralPriv.D)
	tA = util.Add(selfStaticPriv.D, tA)
	k1 := util.Mul(sm2H, tA)
	k1 = util.Mod(k1, selfStaticPriv.Curve.N)
	k2 := util.Mul(k1, x2)
	k2 = util.Mod(k2, selfStaticPriv.Curve.N)

	p1x, p1y := selfStaticPriv.Curve.ScalarMult(otherStaticPub.X, otherStaticPub.Y, k1.Bytes())
	p2x, p2y := selfStaticPriv.Curve.ScalarMult(otherEphemeralPub.X, otherEphemeralPub.Y, k2.Bytes())
	x, y = selfStaticPriv.Curve.Add(p1x, p1y, p2x, p2y)
	return
}

// kdfForExch 为秘钥派生函数，其中输入参数为:
// (1) digest 为哈希函数哈希值实例，采用SM3算法，产生256位哈希值
// (2) ux, uy 为共享秘钥关键点U的有限域坐标
// (3) za, zb 为交换秘钥双方按国标规定生成的识别字, 例如：Za = H256 (ENTLa || IDa || a || b || XG || YG || xa || ya)
// (4) keyBits 为秘钥位数长度
// 输出值为: 长度为keyBit的秘钥位串
// 算法核心逻辑：
// (1) 按目标输出秘钥位数长度klen整除哈希算法输出值位数v的次数(klen/v向上取整)，取输入值Z加“盐”的哈希，
// (2) 每次哈希运算所加入的“盐”，为32位计数器ct所计次数(i=1,2...ceiling(klen/v))
// (3) 将历次哈希运算结果首位相接，形成位串
// (4) 对于运算结果超出klen目标长度的部分，截尾丢弃，或者说，最后的位串，靠左取值
// 例如：SM3输出256位哈希值，而SM4秘钥为128位，则仅需要进行1次加盐哈希运算，然后，将哈希值取前128位，即可输出
func kdfForExch(digest hash.Hash, ux, uy *big.Int, za, zb []byte, keyBits int) []byte {
	bufSize := 4                      // 4字节，32位运算的字长
	if bufSize < digest.BlockSize() { // 分组字节长度，对于SM3而言，为32
		bufSize = digest.BlockSize()
	}
	buf := make([]byte, bufSize)

	rv := make([]byte, (keyBits+7)/8) // 按klen向上取整创设字节数组, result value
	rvLen := len(rv)                  // 对SM4而言，为16，代表128位长度
	uxBytes := ux.Bytes()             // 将big.Int转换成[]byte
	uyBytes := uy.Bytes()
	off := 0
	ct := uint32(0)
	for off < rvLen {
		digest.Reset()
		digest.Write(uxBytes)
		digest.Write(uyBytes)
		digest.Write(za)
		digest.Write(zb)
		ct++
		binary.BigEndian.PutUint32(buf, ct) // 缓存数组buf用了两次: 转换计数器 + 周转哈希值
		digest.Write(buf[:4])
		tmp := digest.Sum(nil) // len(tmp) == bufSize
		copy(buf[:bufSize], tmp[:bufSize])

		if rvlen <= bufSize {
			copyLen := rvLen - off // 仅适用于 rvlen <= bufSize 情形
			copy(rv[off:off+copyLen], buf[:copyLen])
			off += copyLen
		} else {
			copyLen := bufSize // 新增加内容，其实，国密算法中，哈希函数SM3为256位，而SM2为256位、SM4为128位，因此，不适用
			copy(rv[off:off+copyLen], buf[:copyLen])
			off += bufSize
		}
	}
	return rv
}

// calculateInnerHash 为计算S值时的中间哈希函数(详见国标6.1.B8/A9)
// 输出的哈希值为: Hash (Xu || Za || Zb || x1 || y1 || x2 || y2)
func calculateInnerHash(digest hash.Hash, ux *big.Int, za, zb []byte, p1x, p1y *big.Int, p2x, p2y *big.Int) []byte {
	digest.Reset()
	digest.Write(ux.Bytes())
	digest.Write(za)
	digest.Write(zb)
	digest.Write(p1x.Bytes())
	digest.Write(p1y.Bytes())
	digest.Write(p2x.Bytes())
	digest.Write(p2y.Bytes())
	return digest.Sum(nil)
}

// s1 为根据协商应答者临时公钥、公钥、Z值等参数推算的可选校验值，其输入值头部标签为0x02
func s1(digest hash.Hash, uy *big.Int, innerHash []byte) []byte {
	digest.Reset()
	digest.Write([]byte{0x02})
	digest.Write(uy.Bytes())
	digest.Write(innerHash)
	return digest.Sum(nil)
}

// s2 为根据协商发起者临时公钥、公钥、Z值等参数推算的可选校验值，其输入值头部标签为0x03
func s2(digest hash.Hash, uy *big.Int, innerHash []byte) []byte {
	digest.Reset()
	digest.Write([]byte{0x03})
	digest.Write(uy.Bytes())
	digest.Write(innerHash)
	return digest.Sum(nil)
}

// CalculateKeyWithConfirmation 为SM2秘钥交换算法的主函数入口，其中：
// 1. 前部为准备函数, 基于用户ID、ENTL、基础曲线参数和公钥，准备Z值
// 2. 后半部按国标算法，推算关键点U，进而推算Key、S1和S2
// 3. 当协商发起人调用时，应当已经获得对方应答的Sb值，进而需要校验Sb == S1
// 4. 若不是发起人，则调用时仅需要计算得出Key、S1、Sb，无需在本函数中校验S值
func CalculateKeyWithConfirmation(initiator bool, keyBits int, confirmationTag []byte,
	selfStaticPriv *PrivateKey, selfEphemeralPriv *PrivateKey, selfId []byte,
	otherStaticPub *PublicKey, otherEphemeralPub *PublicKey, otherId []byte) (*ExchangeResult, error) {
	if selfId == nil {
		selfId = make([]byte, 0)
	}
	if otherId == nil {
		otherId = make([]byte, 0)
	}
	if initiator && confirmationTag == nil {
		return nil, errors.New("if initiating, confirmationTag must be set")
	}

	selfStaticPub := CalculatePubKey(selfStaticPriv)
	digest := sm3.New()
	za := getZ(digest, &selfStaticPriv.Curve, selfStaticPub.X, selfStaticPub.Y, selfId)
	zb := getZ(digest, &selfStaticPriv.Curve, otherStaticPub.X, otherStaticPub.Y, otherId)

	w := selfStaticPriv.Curve.BitSize/2 - 1
	selfEphemeralPub := CalculatePubKey(selfEphemeralPriv)
	ux, uy := calculateU(w, selfStaticPriv, selfEphemeralPriv, selfEphemeralPub, otherStaticPub, otherEphemeralPub)
	if initiator {
		rv := kdfForExch(digest, ux, uy, za, zb, keyBits)
		innerHash := calculateInnerHash(digest, ux, za, zb, selfEphemeralPub.X, selfEphemeralPub.Y,
			otherEphemeralPub.X, otherEphemeralPub.Y)
		s1 := s1(digest, uy, innerHash)
		if !bytes.Equal(s1, confirmationTag) { // 比较Sb和S1值是否相等
			return nil, errors.New("confirmation tag mismatch")
		}
		s2 := s2(digest, uy, innerHash)
		return &ExchangeResult{Key: rv, S2: s2}, nil
	} else {
		rv := kdfForExch(digest, ux, uy, zb, za, keyBits)
		innerHash := calculateInnerHash(digest, ux, zb, za, otherEphemeralPub.X, otherEphemeralPub.Y,
			selfEphemeralPub.X, selfEphemeralPub.Y)
		s1 := s1(digest, uy, innerHash)
		s2 := s2(digest, uy, innerHash)
		return &ExchangeResult{Key: rv, S1: s1, S2: s2}, nil
	}
}

// ResponderConfim 为秘钥协商应答主体调用的S值校验函数(国标6.1.B10)
func ResponderConfirm(responderS2 []byte, initiatorS2 []byte) bool {
	return bytes.Equal(responderS2, initiatorS2)
}
