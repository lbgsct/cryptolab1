// task6_deal.go

package main

import (
	"errors"
	"fmt"
)

// DEAL структура, представляющая алгоритм DEAL
type DEAL struct {
	feistel *FeistelNetwork
}

// NewDEAL создает новый экземпляр DEAL
func NewDEAL() (*DEAL, error) {
	keySchedule := &DEALKeySchedule{}
	roundFunction := NewDEALRoundFunction()

	// Количество раундов зависит от длины ключа; здесь используется 6 раундов для примера
	feistel := NewFeistelNetwork(6, keySchedule, roundFunction)
	deal := &DEAL{
		feistel: feistel,
	}

	return deal, nil
}

// SetKey устанавливает ключ для алгоритма DEAL
func (deal *DEAL) SetKey(key []byte) error {
	return deal.feistel.SetKey(key)
}

// Encrypt шифрует блок данных
func (deal *DEAL) Encrypt(block []byte) ([]byte, error) {
	return deal.feistel.Encrypt(block)
}

// Decrypt дешифрует блок данных
func (deal *DEAL) Decrypt(block []byte) ([]byte, error) {
	return deal.feistel.Decrypt(block)
}

// DEALKeySchedule реализует интерфейс KeyRound для DEAL
type DEALKeySchedule struct{}

// GenerateKeys генерирует раундовые ключи для DEAL
// GenerateKeys генерирует раундовые ключи для DEAL
func (ks *DEALKeySchedule) GenerateKeys(inputKey []byte) ([][]byte, error) {
	keyLength := len(inputKey)
	var numRounds int

	// Определяем количество раундов на основе длины ключа
	switch keyLength {
	case 16:
		numRounds = 6
	case 24:
		numRounds = 8
	case 32:
		numRounds = 12
	default:
		return nil, errors.New("key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
	}

	// Генерируем раундовые ключи
	roundKeys := make([][]byte, numRounds)

	// Разделение ключа на части для раундов
	for i := 0; i < numRounds; i++ {
		start := (i * 8) % keyLength
		end := start + 8
		if end > keyLength {
			end = keyLength
		}

		// Берём часть ключа и дополняем, если она меньше 8 байт
		part := inputKey[start:end]
		if len(part) < 8 {
			padding := make([]byte, 8-len(part))
			part = append(part, padding...)
		}

		roundKeys[i] = part

		// Отладочный вывод
		fmt.Printf("Round %d Key: %x (Length: %d bytes)\n", i+1, part, len(part))
	}

	return roundKeys, nil
}


// DEALRoundFunction реализует интерфейс CipherTransform для DEAL
type DEALRoundFunction struct {
	des *DES
}

// NewDEALRoundFunction создает новый адаптер DES для DEAL
func NewDEALRoundFunction() *DEALRoundFunction {
	des, _ := NewDES()
	return &DEALRoundFunction{des: des}
}

func (rf *DEALRoundFunction) Encryption(inputBlock, roundKey []byte) ([]byte, error) {
	if len(roundKey) != 8 {
		return nil, errors.New("round key must be 8 bytes (64 bits)")
	}

	// Устанавливаем раундовый ключ для DES
	err := rf.des.SetKey(roundKey)
	if err != nil {
		return nil, err
	}

	// Шифруем входной блок с помощью DES
	return rf.des.Encrypt(inputBlock)
}

func (rf *DEALRoundFunction) Decryption(inputBlock, roundKey []byte) ([]byte, error) {
	if len(roundKey) != 8 {
		return nil, errors.New("round key must be 8 bytes (64 bits)")
	}

	// Устанавливаем раундовый ключ для DES
	err := rf.des.SetKey(roundKey)
	if err != nil {
		return nil, err
	}

	// Дешифруем входной блок с помощью DES
	return rf.des.Decrypt(inputBlock)
}

// EncryptAsync выполняет асинхронное шифрование данных
func (deal *DEAL) EncryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		encryptedData, err := deal.Encrypt(data)
		if err != nil {
			errChan <- err
			close(resultChan)
			close(errChan)
			return
		}
		resultChan <- encryptedData
		close(resultChan)
		close(errChan)
	}()

	return resultChan, errChan
}

// DecryptAsync выполняет асинхронное дешифрование данных
func (deal *DEAL) DecryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		decryptedData, err := deal.Decrypt(data)
		if err != nil {
			errChan <- err
			close(resultChan)
			close(errChan)
			return
		}
		resultChan <- decryptedData
		close(resultChan)
		close(errChan)
	}()

	return resultChan, errChan
}
