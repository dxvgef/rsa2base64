package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

func main() {
	log.SetFlags(log.Lshortfile)

	var (
		err       error
		output    string
		fileBytes []byte
		blocks    []*pem.Block
	)

	flag.Parse()
	if flag.Arg(0) == "" {
		fmt.Println("没有指定要转换的文件")
		return
	}

	fileBytes, err = ioutil.ReadFile(filepath.Clean(flag.Arg(0)))
	if err != nil {
		log.Println(err.Error())
		return
	}
	blocks = parsePEMBlocks(fileBytes)
	if len(blocks) == 0 {
		fmt.Println("指定的文件不是有效的RSA公钥或私钥")
		return
	}

	switch blocks[0].Type {
	case "PUBLIC KEY":
		var publicKey *rsa.PublicKey
		fmt.Println("[" + blocks[0].Type + "]")
		publicKey, err = parseRSAPublicKey(blocks[0].Bytes)
		if err != nil {
			log.Println(err.Error())
			return
		}
		output, err = base64EncodeRSAPublicKey(publicKey)
		if err != nil {
			log.Println(err.Error())
			return
		}
		fmt.Println(output)
	case "RSA PRIVATE KEY", "PRIVATE KEY":
		fmt.Println("[" + blocks[0].Type + "]")
		var privateKey *rsa.PrivateKey
		var pkcsVersion string
		privateKey, pkcsVersion, err = parseRSAPrivateKey(blocks[0].Bytes)
		if err != nil {
			log.Println(err.Error())
			return
		}
		output, err = base64EncodeRSAPrivateKey(privateKey, pkcsVersion)
		if err != nil {
			log.Println(err.Error())
			return
		}
		fmt.Println(output)
	default:
		fmt.Println("指定的文件不是有效的RSA公钥或私钥")
	}
}

// Base64编码RSA Private key为字符串
func base64EncodeRSAPrivateKey(privateKey *rsa.PrivateKey, pkcsVersion string) (string, error) {
	var keyBytes []byte
	var err error

	pkcsVersion = strings.ToUpper(pkcsVersion)
	switch pkcsVersion {
	case "PKCS1":
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	case "PKCS8":
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return "", err
		}
	default:
		return "", errors.New("仅支持转为PKCS的1和8版本的密钥")
	}
	keyStr := base64.StdEncoding.EncodeToString(keyBytes)
	return keyStr, nil
}

// Base64编码RSA Public key为字符串
func base64EncodeRSAPublicKey(publicKey *rsa.PublicKey) (string, error) {
	keyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	keyStr := base64.StdEncoding.EncodeToString(keyBytes)
	return keyStr, nil
}

// Base64字符串解码成RSA Private Key
func base64DecodePrivateKey(base64Str string) (*rsa.PrivateKey, string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, "", err
	}

	privateKey, keyType, err := parseRSAPrivateKey(keyBytes)
	if err != nil {
		return nil, "", err
	}

	return privateKey, keyType, nil
}

// Base64字符串解码成RSA Public Key
func base64DecodePublicKey(base64Str string) (*rsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// parsePEMBlocks 解析PEM区块
func parsePEMBlocks(data []byte) []*pem.Block {
	var (
		blocks []*pem.Block
		block  *pem.Block
		rest   []byte
	)
	block, rest = pem.Decode(data)
	if block != nil {
		blocks = append(blocks, block)
		for len(rest) > 0 {
			block, rest = pem.Decode(rest)
			if block != nil {
				blocks = append(blocks, block)
			}
		}
	}
	return blocks
}

// parseRSAPublicKey 解析RSA公钥
func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	var err error
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(data); err != nil {
		if cert, err := x509.ParseCertificate(data); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var publicKey *rsa.PublicKey
	var ok bool
	if publicKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("不是有效的RSA公钥")
	}

	return publicKey, nil
}

// 解析RSA私钥，自动识别PKCS1和PKCS8
func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, string, error) {
	var (
		err         error
		parsedKey   interface{}
		pkcsVersion = "PKCS1"
		privateKey  *rsa.PrivateKey
		ok          bool
	)

	// 尝试PKCS1
	parsedKey, err = x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		if err.Error() != "x509: failed to parse private key (use parsePKCS8PrivateKey instead for this key format)" {
			return nil, "", err
		}
		parsedKey, err = x509.ParsePKCS8PrivateKey(data)
		if err != nil {
			return nil, "", err
		}
		pkcsVersion = "PKCS8"
	}

	if privateKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, "", errors.New("不是有效的RSA私钥")
	}

	return privateKey, pkcsVersion, nil
}
