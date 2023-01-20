package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/maximthomas/gortas/pkg/config"
	"github.com/pkg/errors"
)

func EncryptWithConfig(message string) (encmess string, err error) {
	encKey := config.GetConfig().EncryptionKey
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return "", errors.Wrap(err, "error encrypt wuth config")
	}
	return Encrypt(key, message)
}

func DecryptWithConfig(message string) (encmess string, err error) {
	encKey := config.GetConfig().EncryptionKey
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return "", errors.Wrap(err, "error encrypt wuth config")
	}
	return Decrypt(key, message)
}

func Encrypt(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func Decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func MD5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func RandomString(length int, useLetters, useDigits bool) (string, error) {
	var runes string
	if useLetters {
		runes += "abcdefghijklmnopqrstuvwxyz"
	}
	if useDigits {
		runes += "0123456789"
	}

	if runes == "" {
		return "", errors.New("at least letters or numbers should be specified")
	}
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(runes))))
		if err != nil {
			return "", err
		}
		ret[i] = runes[num.Int64()]
	}
	return string(ret), nil
}
