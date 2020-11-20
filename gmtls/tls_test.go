// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"strings"
	"testing"
)

var sm2CertPEM = `-----BEGIN CERTIFICATE-----
MIICLTCCAdOgAwIBAgIRANRjDNMgvsXUcosX+3eGKKswCgYIKoEcz1UBg3UwbTEL
MAkGA1UEBhMCQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcx
GTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHzAdBgNVBAMTFnRsc2NhLm9yZzEu
ZXhhbXBsZS5jb20wHhcNMjAxMTE5MDY0MzAwWhcNMzAxMTE3MDY0MzAwWjBSMQsw
CQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEf
MB0GA1UEAwwWQWRtaW5Ab3JnMS5leGFtcGxlLmNvbTBcMBYGCSqBHM9VAYItAQYJ
KoEcz1UBgi0FA0IABOGoxhWPAAetlf+lOze/FHar/pTH31xbG0PTwtD71lughgqo
b26Hugb4hkpdUSfFhk+Xq1C0/UI7LKBeuDHuMECjbDBqMA4GA1UdDwEB/wQEAwIF
oDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAr
BgNVHSMEJDAigCAQPO0Ydwl/LNb/plx+S5UZ0d77s0BMzGJLWJoGC4aODzAKBggq
gRzPVQGDdQNIADBFAiEAsw6bTPY6pRqqyJhxwC2RwECeyg5N2ULsgnqb5sWxzCcC
IAWbHJMBQ+8Pc25duMRmzJivb0xXhxbtB3N52E1FifH1
-----END CERTIFICATE-----
`

var sm2KeyPEM = `-----BEGIN SM2 PRIVATE KEY-----
MIGXAgEAMBYGCSqBHM9VAYItAQYJKoEcz1UBgi0FBHoweAIBAQQgDRuKIgg0T8um
o6yJqjnT1trrIUUPojle4WQZzvWAV2ygCwYJKoEcz1UBgi0FoUQDQgAE4ajGFY8A
B62V/6U7N78Udqv+lMffXFsbQ9PC0PvWW6CGCqhvboe6BviGSl1RJ8WGT5erULT9
QjssoF64Me4wQA==
-----END SM2 PRIVATE KEY-----
`

var keyPairTests = struct {
	algo string
	cert string
	key  string
}{"SM2", sm2CertPEM, sm2KeyPEM}

func TestX509KeyPair(t *testing.T) {
	t.Parallel()
	var pem []byte
	// test := keyPairTests
	pem = []byte(sm2CertPEM + sm2KeyPEM)
	if _, err := X509KeyPair(pem, pem); err != nil {
		t.Errorf("Failed to load %s cert followed by %s key: %s", "SM2", "SM2", err)
	}
	pem = []byte(sm2KeyPEM + sm2CertPEM)
	if _, err := X509KeyPair(pem, pem); err != nil {
		t.Errorf("Failed to load %s key followed by %s cert: %s", "SM2", "SM2", err)
	}
}

func TestX509KeyPairErrors(t *testing.T) {
	_, err := X509KeyPair([]byte(sm2KeyPEM), []byte(sm2CertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when arguments were switched")
	}
	if subStr := "been switched"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when switching arguments to X509KeyPair, but the error was %q", subStr, err)
	}

	_, err = X509KeyPair([]byte(sm2CertPEM), []byte(sm2CertPEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were certificates")
	}
	if subStr := "certificate"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were certificates, but the error was %q", subStr, err)
	}

	const nonsensePEM = `
-----BEGIN NONSENSE-----
Zm9vZm9vZm9v
-----END NONSENSE-----
`

	_, err = X509KeyPair([]byte(nonsensePEM), []byte(nonsensePEM))
	if err == nil {
		t.Fatalf("X509KeyPair didn't return an error when both arguments were nonsense")
	}
	if subStr := "NONSENSE"; !strings.Contains(err.Error(), subStr) {
		t.Fatalf("Expected %q in the error when both arguments to X509KeyPair were nonsense, but the error was %q", subStr, err)
	}
}
