package gmx509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/paul-lee-attorney/gm/sm2"
)

// CreateCertificatePEM 返回用PEM编码格式存储的certificate
func CreateCertificatePEM() ([]byte, error) {

	pri, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidExtensionSubjectAltName,
				Value: sanContents,
			},
		},
	}

	pub := &pri.PublicKey
	derBytes, err := CreateCertificateRequest(&template, pub, pri, nil)
	if err != nil {
		return nil, err
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	cerTemplate := x509.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		NotBefore:    time.Now(),
		NotAfter:     time.Unix(time.Now().Unix()+100000000, 0),

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},
	}

	FillCertificateTemplateByCSR(&cerTemplate, csr)

	cBytes, err := CreateCertificateBytes(&cerTemplate, &cerTemplate, pub, pri)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "SM2 CERTIFICATE",
			Bytes: cBytes,
		},
	), nil
}
