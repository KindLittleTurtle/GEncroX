//GEncroX/key.go

//MIT License
//
//Copyright (c) 2023 核善的小兲
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

package GEncroX

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// PrivateKeyToPEM 将私钥编码为PEM格式的字符串
func PrivateKeyToPEM(KeyType string, PrivateKey interface{}) ([]byte, error) {
	PrivateKeyBytes, err := x509.MarshalPKCS8PrivateKey(PrivateKey)
	if err != nil {
		return nil, errors.New("错误: 转换为 ASN.1 DER 编码形式失败，可能是私钥损坏")
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: KeyType, Bytes: PrivateKeyBytes})
	if err != nil {
		return nil, errors.New("错误: 转换私钥格式失败")
	}

	return buf.Bytes(), nil
}

// PublicKeyToPEM 将公钥编码为PEM格式的字符串
func PublicKeyToPEM(KeyType string, PublicKey interface{}) ([]byte, error) {
	PublicKeyBytes, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		return nil, errors.New("错误: 转换为 ASN.1 DER 编码形式失败，可能是公钥损坏")
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: KeyType, Bytes: PublicKeyBytes})
	if err != nil {
		return nil, errors.New("错误: 转换公钥格式失败")
	}

	return buf.Bytes(), nil
}

// ParsePEMPrivateKey 解码PEM格式的私钥
func ParsePEMPrivateKey(PEMKey []byte) (interface{}, error) {
	PEMKeyP := &PEMKey
	block, _ := pem.Decode(*PEMKeyP)
	if block == nil {
		return nil, errors.New("错误: PEM解析失败，可能是密钥损坏")
	}

	Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("错误: 解析私钥失败，可能是私钥损坏或密钥类型错误")
	}

	return Key, nil
}

// ParsePEMPublicKey 解码PEM格式的公钥
func ParsePEMPublicKey(PEMKey []byte) (interface{}, error) {
	PEMKeyP := &PEMKey
	block, _ := pem.Decode(*PEMKeyP)
	if block == nil {
		return nil, errors.New("错误: PEM解析失败，可能是密钥损坏")
	}

	Key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("错误: 解析公钥失败，可能是公钥损坏或密钥类型错误")
	}

	return Key, nil
}
