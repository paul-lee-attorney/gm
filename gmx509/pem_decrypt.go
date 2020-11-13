/*
Copyright Paul Lee. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gmx509

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
)

// SM2PrivateKeyToPEM converts sm2 private key to PEM format.
// EC private keys are converted to PKCS#8 format.
func SM2PrivateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return Sm2PrivateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}

		pkcs8Bytes, err := MarshalPKCS8SM2PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "SM2 PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil
	default:
		return nil, errors.New("Invalid key type. It must be *sm2.PrivateKey")
	}
}

// Sm2PrivateKeyToEncryptedPEM converts a private key into an encrypted PEM
func Sm2PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil")
		}

		raw, err := MarshalSM2PrivateKey(k)
		if err != nil {
			return nil, err
		}

		blockType := "SM2 PRIVATE KEY"

		block, err := Sm4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

	default:
		return nil, errors.New("Invalid key type. It must be *sm2.PrivateKey")
	}
}

// PEMtoSM2PrivateKey unmarshals a pem to SM2 private key
func PEMtoSM2PrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Need a password")
		}

		decrypted, err := Sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
		}

		key, err := ParseSM2PrivateKey(decrypted)
		if err != nil {
			return nil, err
		}

		return key, err
	}

	cert, err := ParsePKCS8SM2PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// SM4toPEM encapsulates a SM4 key in the PEM format
func SM4toPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// PEMtoSM4 extracts from the PEM an SM4 private key
func PEMtoSM4(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different from nil")
		}

		decrypted, err := Sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

// SM4toEncryptedPEM encapsulates a SM4 key in the encrypted PEM format
func SM4toEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return SM4toPEM(raw), nil
	}

	blockType := "SM4 PRIVATE KEY"

	pem, err := Sm4EncryptPEMBlock(blockType, raw, pwd)

	if err != nil {
		return nil, err
	}

	return pem, nil
}

// Sm4EncryptPEMBlock encrypt raw message into PEM format via SM4. refer: x509.EncryptPEMBlock()
// 将输入消息用SM4加密并转化为PEM格式的函数。
func Sm4EncryptPEMBlock(blockType string, raw []byte, pwd []byte) ([]byte, error) {

	if len(raw) == 0 || raw == nil {
		return nil, errors.New("Invalid SM4 key. It must be different from nil")
	}
	if len(pwd) == 0 || pwd == nil {
		return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw}), nil
	}

	// SM4的秘钥长度16字节，128位
	blockSize := 16

	// 按秘钥长度创设初始向量iv切片
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("x509: cannot generate IV: " + err.Error())
	}

	// The salt is the first 8 bytes of the initialization vector,
	// matching the key derivation in DecryptPEMBlock.
	key := deriveKey(pwd, iv[:8])

	encrypted, err := SM4CBCPKCS7EncryptWithIV(iv, key, raw)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "SM4CBCPKCS7" + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}

	return pem.EncodeToMemory(block), nil
}

// Sm4DecryptPEMBlock decrypt PEM block via SM4.
// 将输入消息用SM4加密并转化为PEM格式的函数, 其中密文格式采用CBC模式，PKCS7规范填充尾部字节。
func Sm4DecryptPEMBlock(block *pem.Block, pwd []byte) ([]byte, error) {

	if len(pwd) == 0 || pwd == nil {
		return nil, errors.New("password shall not be nil")
	}

	// 读取加密密码算法信息
	dek, _ := block.Headers["DEK-Info"]

	// 获取标识符","的位置
	idx := strings.Index(dek, ",")
	if idx == -1 {
		return nil, errors.New("x509: malformed DEK-Info header")
	}

	// 获取CBC加密的初始向量值iv
	hexIV := dek[idx+1:]
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}

	// 根据OpenSSL源代码，向量初始值的前八位为“盐”，利用SM3取哈希值
	// 截取哈希值前16字节，进而获得SM4加密秘钥
	key := deriveKey(pwd, iv[:8])

	data, err := SM4CBCPKCS7Decrypt(key, block.Bytes)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// deriveKey 为秘钥派生函数，参考Openssl和go标准库，用SM3为哈希函数
// 将密码加盐（初始向量前8字节）取SM3哈希后，将哈希值前16位取出作为SM4秘钥使用。
// 不同于SM2国标派生函数的32位计数器加盐，与Fabric内置算法保持一致。
func deriveKey(password, salt []byte) []byte {
	hash := sm3.New() // SM4 秘钥长度为128位，16字节，而SM3只能生成256位哈希值
	out := make([]byte, 16)

	hash.Reset()
	hash.Write(password)
	hash.Write(salt)
	digest := hash.Sum(nil)

	copy(out, digest[:16]) // 截取SM3前16字节为SM4秘钥

	return out
}

// PemToSM2PublicKey unmarshals a pem to public key
func PemToSM2PublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different from nil")
		}

		decrypted, err := Sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		key, err := ParsePKIXSM2PublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := ParsePKIXSM2PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// SM2PublicKeyToPEM marshals a public key to the pem format
func SM2PublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return SM2PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid SM2 public key. It must be different from nil")
		}

		PubASN1, err := MarshalPKIXSM2PublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "SM2 PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	default:
		return nil, errors.New("Invalid key type. It must be *sm2.PublicKey")
	}
}

// SM2PublicKeyToEncryptedPEM converts a public key to encrypted pem
func SM2PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return nil, errors.New("Invalid password. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil")
		}
		raw, err := MarshalPKIXSM2PublicKey(k)
		if err != nil {
			return nil, err
		}

		blockType := "MS2 PUBLIC KEY"

		block, err := Sm4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}
