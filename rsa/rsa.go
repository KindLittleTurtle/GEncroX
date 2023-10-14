//GEncroX/rsa/rsa.go

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

package rsa

import (
	"GEncroX/aes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

// GenerateKeyPair 生成RSA密钥对
func GenerateKeyPair(bits int) (RSAPrivateKey *PrivateKey, RSAPublicKey *PublicKey, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, errors.New("生成RSA密钥对失败")
	}

	publicKey := &privateKey.PublicKey

	RSAPrivateKey = &PrivateKey{
		privateKey,
	}

	RSAPublicKey = &PublicKey{
		publicKey,
	}

	return RSAPrivateKey, RSAPublicKey, nil
}

// Encrypt 使用RSA公钥加密文本
func Encrypt(plaintext []byte, RSAPublicKey *PublicKey) (ciphertext []byte, err error) {
	publicKey := RSAPublicKey.Key

	// 生成AES密钥
	aesKey := make([]byte, 32)
	_, err = rand.Read(aesKey)
	if err != nil {
		return nil, errors.New("生成AES密钥失败")
	}

	// 使用AES加密文本
	ciphertext, err = aes.Encrypt(plaintext, aesKey)
	if err != nil {
		return nil, err
	}

	// 使用公钥加密AES密钥
	cipherKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
	if err != nil {
		return nil, errors.New("RSA加密AES密钥失败")
	}

	ciphertext = append(cipherKey, ciphertext...)

	return ciphertext, nil
}

// Decrypt 使用RSA私钥解密密文
func Decrypt(ciphertext []byte, RSAPrivateKey *PrivateKey) (plaintext []byte, err error) {
	privateKey := RSAPrivateKey.Key

	// 分离密文中的AES密钥和实际密文
	cipherKey := ciphertext[:256]
	ciphertext = ciphertext[256:]

	// 使用私钥解密AES密钥
	plainKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherKey)
	if err != nil {
		return nil, errors.New("RSA解密AES密钥失败")
	}

	// 使用AES解密实际密文
	plaintext, err = aes.Decrypt(ciphertext, plainKey)
	if err != nil {
		return nil, errors.New("AES解密失败")
	}

	return plaintext, nil
}
