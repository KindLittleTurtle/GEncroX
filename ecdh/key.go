//GEncroX/ecdh/key.go

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
	"crypto/ecdsa"
	"errors"
	"github.com/KindLittleTurtle/GEncroX"
)

type PrivateKey struct {
	Key *ecdh.PrivateKey
}

func (PrivateKey *PrivateKey) ToPEM() (PEMKey []byte, err error) {
	PEMKey, err = GEncroX.PrivateKeyToPEM("ECC PRIVATE KEY", PrivateKey.Key)
	if err != nil {
		return nil, err
	}

	return PEMKey, nil
}

type PublicKey struct {
	Key *ecdh.PublicKey
}

func (PublicKey *PublicKey) ToPEM() (PEMKey []byte, err error) {
	PEMKey, err = GEncroX.PublicKeyToPEM("ECC PUBLIC KEY", PublicKey.Key)
	if err != nil {
		return nil, err
	}

	return PEMKey, nil
}

func PEMKeyToPrivateKey(PEMKey []byte) (ECCPrivateKey *PrivateKey, err error) {
	Key, err := GEncroX.ParsePEMPrivateKey(PEMKey)
	if err != nil {
		return nil, err
	}

	EcdsaPrivateKey, ok := Key.(*ecdsa.PrivateKey)
	if !ok {
		EcdhPrivateKey, ok := Key.(*ecdh.PrivateKey)
		if !ok {
			return nil, errors.New("错误: 解析私钥失败，可能是私钥损坏或密钥类型错误")
		}

		ECCPrivateKey = &PrivateKey{
			EcdhPrivateKey,
		}

		return ECCPrivateKey, nil
	}

	EcdhPrivateKey, err := EcdsaPrivateKey.ECDH()
	if err != nil {
		return nil, errors.New("错误: 不支持的曲线类型")
	}

	ECCPrivateKey = &PrivateKey{
		EcdhPrivateKey,
	}

	return ECCPrivateKey, nil
}

func PEMKeyToPublicKey(PEMKey []byte) (ECCPublicKey *PublicKey, err error) {
	Key, err := GEncroX.ParsePEMPublicKey(PEMKey)
	if err != nil {
		return nil, err
	}

	EcdsaPublicKey, ok := Key.(*ecdsa.PublicKey)
	if !ok {
		EcdhPublicKey, ok := Key.(*ecdh.PublicKey)
		if !ok {
			return nil, errors.New("错误: 解析私钥失败，可能是公钥损坏或密钥类型错误")
		}

		ECCPublicKey = &PublicKey{
			EcdhPublicKey,
		}

		return ECCPublicKey, nil
	}

	EcdhPublicKey, err := EcdsaPublicKey.ECDH()
	if err != nil {
		return nil, errors.New("错误: 不支持的曲线类型")
	}

	ECCPublicKey = &PublicKey{
		EcdhPublicKey,
	}

	return ECCPublicKey, nil
}
