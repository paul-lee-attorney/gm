/*
Copyright Paul Lee. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gmx509

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/paul-lee-attorney/gm/sm2"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// MarshalPKIXSM2PublicKey converts a SM2 public key to PKIX, ASN.1 DER form.
// 将SM2公钥转换成符合PKIX, ASN.1 DER编码规则的形式.
func MarshalPKIXSM2PublicKey(pub *sm2.PublicKey) ([]byte, error) {

	if pub == nil {
		return nil, errors.New("input sm2 public key shall not be nil")
	}

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	publicKeyBytes = pub.GetUnCompressBytes()

	publicKeyAlgorithm.Algorithm = oidPublicKeySM2DSA

	paramBytes, err := asn1.Marshal(oidSM2P256V1)
	if err != nil {
		return nil, err
	}

	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParsePKIXSM2PublicKey parse a DER-encoded ASN.1 data into SM2 public key object.
// 将符合PKIX, ASN.1 DER编码规则的SM2公钥反序列化为对象.
func ParsePKIXSM2PublicKey(der []byte) (*sm2.PublicKey, error) {

	if len(der) == 0 || der == nil {
		return nil, errors.New("x509: raw materials of SM2 public key shall not be nil")
	}

	var pki publicKeyInfo

	if rest, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	// 校验算法是否属于SM2DSA
	if algo := pki.Algorithm.Algorithm; !algo.Equal(oidPublicKeySM2DSA) {
		return nil, errors.New("the algorithm does not belong to ECDSA ")
	}

	paramsData := pki.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if rest, err := asn1.Unmarshal(paramsData, namedCurveOID); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after SM2 parameters")
	}

	// 校验基础曲线是否为SM2推荐曲线
	if !namedCurveOID.Equal(oidSM2P256V1) {
		return nil, errors.New("x509: CurveOID is not the OID of SM2P256")
	}

	// 初始化并获得SM2曲线
	namedCurve := sm2.GetSM2P256V1()

	// 编码时没有对BitString移位，所以不必右对齐进行调整
	publicKeyBytes := pki.PublicKey.RightAlign()

	// 反序列化SM2曲线和公钥
	x, y := elliptic.Unmarshal(namedCurve, publicKeyBytes)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &sm2.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
