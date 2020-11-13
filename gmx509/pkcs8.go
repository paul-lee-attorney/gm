/*
Copyright Paul Lee based on works of Go Authors.
All rights reserved.
Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.
*/

package gmx509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/paul-lee-attorney/gm/sm2"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8SM2PrivateKey 解析PKCS8格式的采用DER规则编码的SM2私钥.
func ParsePKCS8SM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {

	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}

	if !privKey.Algo.Algorithm.Equal(oidPublicKeySM2DSA) {
		return nil, fmt.Errorf("PKCS#8 wrapping algorithm is note SM2: %v", privKey.Algo.Algorithm)
	}

	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}

	if !namedCurveOID.Equal(oidSM2P256V1) {
		return nil, fmt.Errorf("PKCS#8 wrapped Curve is note the SM2 EC ")
	}

	key, err := ParseSM2PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// MarshalPKCS8SM2PrivateKey convert SM2 private key into PKCS#8 []byte
// ref: crypto/x509/pkcs8.go ---- MarshalPKCS8PrivateKey()
func MarshalPKCS8SM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {

	var privKey pkcs8

	privKey.Version = 0

	oidBytes, err := asn1.Marshal(oidSM2P256V1)
	if err != nil {
		return nil, errors.New("failed to marshal curve OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeySM2DSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	if privKey.PrivateKey, err = MarshalSM2PrivateKey(key); err != nil {
		return nil, errors.New("failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	return asn1.Marshal(privKey)
}
