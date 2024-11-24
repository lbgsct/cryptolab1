package main

import (
	"errors"
)

// перестановка битов в рамках переданного значения
func PermuteBits(value []byte, pBlock []int, flag bool, startBitNumber int) ([]byte, error) {
	totalInputBits := len(value) * 8
	totalOutputBits := len(pBlock)
	output := make([]byte, (totalOutputBits+7)/8)

	for i, pIndex := range pBlock {
		// индекс согласно начальному номеру бита
		adjustedIndex := pIndex - startBitNumber

		if adjustedIndex < 0 || adjustedIndex >= totalInputBits {
			return nil, errors.New("bit index out of range in permutation block")
		}

		var actualBitIndex int
		if flag {
			// биты индексируются от младшего к старшему
			actualBitIndex = adjustedIndex
		} else {
			// биты индексируются от старшего к младшему
			actualBitIndex = totalInputBits - 1 - adjustedIndex
		}

		bitValue, err := getBit(value, actualBitIndex)
		if err != nil {
			return nil, err
		}

		// Устанавливаем бит в выходном массиве
		err = setBit(output, i, bitValue)
		if err != nil {
			return nil, err
		}
	}

	return output, nil
}

func getBit(byteArray []byte, bitIndex int) (int, error) {
	totalBits := len(byteArray) * 8

	if bitIndex < 0 || bitIndex >= totalBits {
		return 0, errors.New("bit index out of range")
	}

	bytePosition := bitIndex / 8
	bitPosition := 7 - (bitIndex % 8) // MSB имеет индекс 0

	bitValue := (byteArray[bytePosition] >> uint(bitPosition)) & 1

	return int(bitValue), nil
}

func setBit(byteArray []byte, bitIndex int, bitValue int) error {
	totalBits := len(byteArray) * 8

	if bitIndex < 0 || bitIndex >= totalBits {
		return errors.New("bit index out of range")
	}

	bytePosition := bitIndex / 8
	bitPosition := 7 - (bitIndex % 8) // MSB имеет индекс 0

	if bitValue == 1 {
		byteArray[bytePosition] |= 1 << uint(bitPosition)
	} else {
		byteArray[bytePosition] &^= 1 << uint(bitPosition)
	}

	return nil
}
