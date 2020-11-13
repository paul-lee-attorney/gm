/*
Copyright Paul Lee. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gmx509

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/paul-lee-attorney/gm/sm2"
)

const ecPrivKeyVersion = 1

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseSM2PrivateKey parses a SM2 in form of SEC 1, ASN.1 DER back to object.
// 解析依照ASN.1规范的椭圆曲线私钥结构定义的SM2.
// ref: crypto/x509/sec1.go ---- ParseECPrivateKey()
func ParseSM2PrivateKey(der []byte) (key *sm2.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("unknown EC private key version %d", privKey.Version)
	}
	if !privKey.NamedCurveOID.Equal(oidSM2P256V1) {
		return nil, fmt.Errorf("the oid does not equal to SM2 EC ")
	}

	curve := sm2.GetSM2P256V1()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("invalid elliptic curve private key value")
	}
	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

// MarshalSM2PrivateKey converts a SM2 private key to SEC 1, ASN.1 DER form.
func MarshalSM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {

	if key == nil {
		return nil, errors.New("x509: input materials for sm2 private key marshalling shall not be nil")
	}

	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, sm2.KeyBytes)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oidSM2P256V1,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}
