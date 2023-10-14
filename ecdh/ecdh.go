//GEncroX/ecdh/ecdh.go

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

package ecdh

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/KindLittleTurtle/GEncroX/aes"
)

// GenerateKeyPair 生成ECC密钥对
//   - curve: 曲线类型，可选值为 P256，P384，P521，X25519
func GenerateKeyPair(curve string) (ECCPrivateKey *PrivateKey, ECCPublicKey *PublicKey, err error) {
	var privateKey *ecdh.PrivateKey

	switch curve {
	case "P256":
		privateKey, err = ecdh.P256().GenerateKey(rand.Reader)
	case "P384":
		privateKey, err = ecdh.P384().GenerateKey(rand.Reader)
	case "P521":
		privateKey, err = ecdh.P521().GenerateKey(rand.Reader)
	case "X25519":
		privateKey, err = ecdh.X25519().GenerateKey(rand.Reader)
	default:
		return nil, nil, errors.New("生成密钥对失败: 不支持的曲线类型")
	}

	if err != nil {
		return nil, nil, errors.New("生成密钥对失败")
	}

	publicKey := privateKey.PublicKey()

	ECCPrivateKey = &PrivateKey{
		privateKey,
	}

	ECCPublicKey = &PublicKey{
		publicKey,
	}

	return ECCPrivateKey, ECCPublicKey, nil
}

// Encrypt 使用ECC密钥对进行加密
func Encrypt(plainText []byte, ECCPrivateKey *PrivateKey, ECCPublicKey *PublicKey) (ciphertext []byte, err error) {
	privateKey := ECCPrivateKey.Key
	publicKey := ECCPublicKey.Key

	key, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, errors.New("ECDH密钥交换失败: 私钥或公钥损坏或类型错误")
	}

	aesKey := sha256.Sum256(key)

	ciphertext, err = aes.Encrypt(plainText, aesKey[:])
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt 使用ECC密钥对进行解密
func Decrypt(cipherText []byte, ECCPrivateKey *PrivateKey, ECCPublicKey *PublicKey) (plaintext []byte, err error) {
	privateKey := ECCPrivateKey.Key
	publicKey := ECCPublicKey.Key

	key, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, errors.New("ECDH密钥交换失败: 私钥或公钥损坏或类型错误")
	}

	aesKey := sha256.Sum256(key)

	plaintext, err = aes.Decrypt(cipherText, aesKey[:])
	if err != nil {
		return nil, errors.New("AES解密失败")
	}

	return plaintext, nil
}
