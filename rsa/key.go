//GEncroX/rsa/key.go

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
	"GEncroX"
	"crypto/rsa"
	"errors"
)

type PrivateKey struct {
	Key *rsa.PrivateKey
}

func (PrivateKey *PrivateKey) ToPEM() (PEMKey []byte, err error) {
	PEMKey, err = GEncroX.PrivateKeyToPEM("RSA PRIVATE KEY", PrivateKey.Key)
	if err != nil {
		return nil, err
	}

	return PEMKey, nil
}

type PublicKey struct {
	Key *rsa.PublicKey
}

func (PublicKey *PublicKey) ToPEM() (PEMKey []byte, err error) {
	PEMKey, err = GEncroX.PublicKeyToPEM("RSA PUBLIC KEY", PublicKey.Key)
	if err != nil {
		return nil, err
	}

	return PEMKey, nil
}

func PEMKeyToPrivateKey(PEMKey []byte) (RSAPrivateKey *PrivateKey, err error) {
	Key, err := GEncroX.ParsePEMPrivateKey(PEMKey)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := Key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("错误: 解析私钥失败，可能是私钥损坏或密钥类型错误")
	}

	RSAPrivateKey = &PrivateKey{
		rsaPrivateKey,
	}

	return RSAPrivateKey, nil
}

func PEMKeyToPublicKey(PEMKey []byte) (RSAPublicKey *PublicKey, err error) {
	Key, err := GEncroX.ParsePEMPublicKey(PEMKey)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := Key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("错误: 解析私钥失败，可能是私钥损坏或密钥类型错误")
	}

	RSAPublicKey = &PublicKey{
		rsaPublicKey,
	}

	return RSAPublicKey, nil
}
