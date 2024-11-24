package main

import (
	"errors"
)

// FeistelNetwork представляет реализацию сети Фейстеля.
type FeistelNetwork struct {
	rounds    int
	KeyRounds KeyRound
	Transform CipherTransform
	roundKeys [][]byte
}

// Конструктор FeistelNetwork
func NewFeistelNetwork(rounds int, KeyRounds KeyRound, Transforms CipherTransform) *FeistelNetwork {
	return &FeistelNetwork{
		rounds:    rounds,
		KeyRounds: KeyRounds,
		Transform: Transforms,
	}
}

// Метод для установки ключа и генерации раундовых ключей
func (fn *FeistelNetwork) SetKey(key []byte) error {
	roundKeys, err := fn.KeyRounds.GenerateKeys(key)
	if err != nil {
		return err
	}
	fn.roundKeys = roundKeys
	return nil
}

// Метод шифрования
func (fn *FeistelNetwork) Encrypt(block []byte) ([]byte, error) {
	if len(block)%2 != 0 {
		return nil, errors.New("block size must be even")
	}

	left := block[:len(block)/2]
	right := block[len(block)/2:]

	for i := 0; i < fn.rounds; i++ {
		roundKey := fn.roundKeys[i]
		fOutput, err := fn.Transform.Encryption(right, roundKey)
		if err != nil {
			return nil, err
		}

		newLeft := xorBytes(left, fOutput)
		left, right = right, newLeft
	}

	// Объединение левой и правой частей
	ciphertext := append(left, right...)
	return ciphertext, nil
}

// Метод дешифрования
func (fn *FeistelNetwork) Decrypt(block []byte) ([]byte, error) {
	if len(block)%2 != 0 {
		return nil, errors.New("block size must be even")
	}

	left := block[:len(block)/2]
	right := block[len(block)/2:]

	for i := fn.rounds - 1; i >= 0; i-- {
		roundKey := fn.roundKeys[i]
		fOutput, err := fn.Transform.Encryption(left, roundKey)
		if err != nil {
			return nil, err
		}

		newRight := xorBytes(right, fOutput)
		right, left = left, newRight
	}

	// Объединение левой и правой частей
	plaintext := append(left, right...)
	return plaintext, nil
}

// Вспомогательная функция для XOR двух срезов байтов
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
