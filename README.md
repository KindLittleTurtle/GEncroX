# GEncroX 开发文档

GEncroX是一个Go语言加密模块，提供了处理RSA和ECDH密钥对以及AES加密的功能。本文档将介绍如何使用GEncroX模块进行加密、解密和密钥管理。

## 安装

要使用GEncroX模块，首先需要将它安装到你的Go项目中。你可以使用`go get`命令来安装：

```shell
go get github.com/KindLittleTurtle/GEncroX
```

然后，在你的Go代码中导入GEncroX模块：

```go
import "github.com/KindLittleTurtle/GEncroX"
```

## RSA 密钥管理

### 生成RSA密钥对

```go
privateKey, publicKey, err := rsa.GenerateKeyPair(bits int)
if err != nil {
    // 处理错误
}
```

- `bits`是密钥的位数，通常可以选择2048或4096。

### 将RSA密钥转换为PEM格式

```go
privateKeyPEM, err := privateKey.ToPEM()
if err != nil {
    // 处理错误
}

publicKeyPEM, err := publicKey.ToPEM()
if err != nil {
    // 处理错误
}
```

### 从PEM格式的密钥恢复RSA密钥

```go
privateKey, err := rsa.PEMKeyToPrivateKey(privateKeyPEM)
if err != nil {
    // 处理错误
}

publicKey, err := rsa.PEMKeyToPublicKey(publicKeyPEM)
if err != nil {
    // 处理错误
}
```

## RSA 加密和解密

### 使用RSA公钥加密文本

```go
ciphertext, err := rsa.Encrypt(plaintext, publicKey)
if err != nil {
    // 处理错误
}
```

### 使用RSA私钥解密密文

```go
plaintext, err := rsa.Decrypt(ciphertext, privateKey)
if err != nil {
    // 处理错误
}
```

## ECDH 密钥管理

### 生成ECC密钥对

```go
privateKey, publicKey, err := ecdh.GenerateKeyPair(curve string)
if err != nil {
    // 处理错误
}
```

- `curve` 是曲线类型，可选值为 "P256"、"P384"、"P521"、"X25519"。

### 将ECC密钥转换为PEM格式

```go
privateKeyPEM, err := privateKey.ToPEM()
if err != nil {
    // 处理错误
}

publicKeyPEM, err := publicKey.ToPEM()
if err != nil {
    // 处理错误
}
```

### 从PEM格式的密钥恢复ECC密钥

```go
privateKey, err := ecdh.PEMKeyToPrivateKey(privateKeyPEM)
if err != nil {
    // 处理错误
}

publicKey, err := ecdh.PEMKeyToPublicKey(publicKeyPEM)
if err != nil {
    // 处理错误
}
```

## ECDH 加密和解密

### 使用ECC密钥对进行加密

```go
ciphertext, err := ecdh.Encrypt(plaintext, privateKey, publicKey)
if err != nil {
    // 处理错误
}
```

### 使用ECC密钥对进行解密

```go
plaintext, err := ecdh.Decrypt(ciphertext, privateKey, publicKey)
if err != nil {
    // 处理错误
}
```

## AES 加密和解密

### 使用AES加密文本

```go
ciphertext, err := aes.Encrypt(plaintext, key)
if err != nil {
    // 处理错误
}
```

### 使用AES解密密文

```go
plaintext, err := aes.Decrypt(ciphertext, key)
if err != nil {
    // 处理错误
}
```

## GitHub 仓库

GEncroX的源代码托管在GitHub上，你可以在以下链接中访问它：

[GEncroX GitHub 仓库](https://github.com/KindLittleTurtle/GEncroX)
当然，为了完善开发文档，我们应该包括开源协议。在你的项目中，你可以在README文件中添加开源协议的说明。以下是一个示例：

## 开源许可证

GEncroX 使用 MIT 许可证。[LICENSE 文件](https://github.com/KindLittleTurtle/GEncroX/blob/main/LICENSE)。

```plaintext
MIT License

Copyright (c) 2023 核善的小兲

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

请确保在你的项目中包含 MIT 许可证，并根据需要对开源代码进行适当的更改，以便与你的项目的具体情况匹配。

## 总结

GEncroX是一个强大的加密模块，提供了RSA和ECDH密钥管理以及AES加密和解密功能。使用本文档中的示例代码，你可以轻松地在你的Go项目中实现加密和解密操作。请确保妥善保管你的密钥，并小心处理加密数据以确保安全性。

