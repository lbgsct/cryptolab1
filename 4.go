// task4_des.go

package main

import (
	"errors"
)

// DES структура, представляющая алгоритм DES
type DES struct {
	feistel   *FeistelNetwork
	blockSize int
}

// NewDES создает новый экземпляр DES
func NewDES() (*DES, error) {
	keySchedule := &DESKeySchedule{}
	roundFunction := &DESRoundFunction{}

	feistel := NewFeistelNetwork(16, keySchedule, roundFunction)
	des := &DES{
		feistel:   feistel,
		blockSize: 16,
	}

	return des, nil
}

// SetKey устанавливает ключ для алгоритма DES
func (des *DES) SetKey(key []byte) error {
	return des.feistel.SetKey(key)
}

// Encrypt шифрует блок данных
func (des *DES) Encrypt(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("block size must be 8 bytes")
	}
	return des.feistel.Encrypt(block)
}

// Decrypt дешифрует блок данных
func (des *DES) Decrypt(block []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.New("block size must be 8 bytes")
	}
	return des.feistel.Decrypt(block)
}

// DESKeySchedule реализует интерфейс KeyRound для DES
type DESKeySchedule struct{}

// GenerateKeys генерирует раундовые ключи для DES
func (ks *DESKeySchedule) GenerateKeys(inputKey []byte) ([][]byte, error) {
	if len(inputKey) != 8 {
		return nil, errors.New("key must be 8 bytes (64 bits)")
	}

	// Перестановка PC-1 (удаление битов четности)
	pc1 := []int{
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,

		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4,
	}

	// Применяем перестановку PC-1
	permutedKeyBits, err := PermuteBitsToBits(inputKey, pc1, false, 1)
	if err != nil {
		return nil, err
	}

	// Разделяем на левую (C) и правую (D) части по 28 бит
	c := permutedKeyBits[:28]
	d := permutedKeyBits[28:]

	// Количество сдвигов для каждого раунда
	shiftSchedule := []int{
		1, 1, 2, 2, 2, 2, 2, 2,
		1, 2, 2, 2, 2, 2, 2, 1,
	}

	// Перестановка PC-2 для получения раундовых ключей
	pc2 := []int{
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32,
	}

	roundKeys := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		// Циклический сдвиг C и D
		c = leftShiftBits(c, shiftSchedule[i])
		d = leftShiftBits(d, shiftSchedule[i])

		// Объединяем C и D
		cd := append(c, d...)

		// Применяем перестановку PC-2
		roundKeyBits, err := permuteBits(cd, pc2)
		if err != nil {
			return nil, err
		}

		// Преобразуем биты в байты
		roundKeyBytes := bitsToBytes(roundKeyBits)
		roundKeys[i] = roundKeyBytes
	}

	return roundKeys, nil
}

// DESRoundFunction реализует интерфейс CipherTransform для DES
type DESRoundFunction struct{}

func (rf *DESRoundFunction) Encryption(rightHalf, roundKey []byte) ([]byte, error) {
	// Шаг 1: Расширение E
	eTable := []int{
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1,
	}

	// Применяем расширение E
	expandedRightBits, err := PermuteBitsToBits(rightHalf, eTable, false, 1)
	if err != nil {
		return nil, err
	}

	// Конвертируем roundKey в биты
	roundKeyBits := bytesToBits(roundKey)

	// Шаг 2: XOR с раундовым ключом
	xorResultBits := xorBits(expandedRightBits, roundKeyBits)

	// Шаг 3: Преобразование с помощью S-блоков
	sBoxResultBits, err := sBoxSubstitution(xorResultBits)
	if err != nil {
		return nil, err
	}

	// Шаг 4: Перестановка P
	pTable := []int{
		16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25,
	}

	permutedResultBits, err := permuteBits(sBoxResultBits, pTable)
	if err != nil {
		return nil, err
	}

	// Преобразуем биты обратно в байты
	outputBytes := bitsToBytes(permutedResultBits)

	return outputBytes, nil
}

func (rf *DESRoundFunction) Decryption(rightHalf, roundKey []byte) ([]byte, error) {
	// В DES раундовая функция одинакова для шифрования и дешифрования
	return rf.Encryption(rightHalf, roundKey)
}

// Вспомогательные функции (leftShiftBits, permuteBits, xorBits, bytesToBits, bitsToBytes, sBoxSubstitution)
// Реализуйте эти функции в соответствии с корректировками, внесенными ранее.

// Реализация функций:

// leftShiftBits выполняет циклический сдвиг влево для среза битов
func leftShiftBits(bits []int, shifts int) []int {
	shifted := make([]int, len(bits))
	copy(shifted, bits)
	for i := 0; i < shifts; i++ {
		firstBit := shifted[0]
		copy(shifted, shifted[1:])
		shifted[len(bits)-1] = firstBit
	}
	return shifted
}

// permuteBits применяет перестановку к срезу битов
func permuteBits(bits []int, table []int) ([]int, error) {
	permuted := make([]int, len(table))
	for i, position := range table {
		if position-1 < 0 || position-1 >= len(bits) {
			return nil, errors.New("bit index out of range in permutation")
		}
		permuted[i] = bits[position-1]
	}
	return permuted, nil
}

// xorBits выполняет побитовое XOR для двух срезов битов
func xorBits(a, b []int) []int {
	result := make([]int, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// bytesToBits преобразует срез байтов в срез битов
func bytesToBits(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i := 0; i < len(data)*8; i++ {
		bitValue := int((data[i/8] >> uint(7-(i%8))) & 1)
		bits[i] = bitValue
	}
	return bits
}

// bitsToBytes преобразует срез битов в срез байтов
func bitsToBytes(bits []int) []byte {
	numBytes := (len(bits) + 7) / 8
	data := make([]byte, numBytes)
	for i := 0; i < len(bits); i++ {
		if bits[i] == 1 {
			data[i/8] |= 1 << uint(7-(i%8))
		}
	}
	return data
}

// sBoxes - таблицы S-блоков для DES
var sBoxes = [8][4][16]int{
	// S-блок 1
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	// S-блок 2
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	// S-блок 3
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	// S-блок 4
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	// S-блок 5
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	// S-блок 6
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	// S-блок 7
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	// S-блок 8
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

// sBoxSubstitution применяет S-блоки к 48-битному входу и возвращает 32-битный выход
func sBoxSubstitution(inputBits []int) ([]int, error) {
	if len(inputBits) != 48 {
		return nil, errors.New("input to S-boxes must be 48 bits")
	}

	outputBits := make([]int, 32)
	for i := 0; i < 8; i++ {
		chunk := inputBits[i*6 : (i+1)*6]
		row := chunk[0]*2 + chunk[5]
		col := chunk[1]*8 + chunk[2]*4 + chunk[3]*2 + chunk[4]
		sValue := sBoxes[i][row][col]

		// Преобразуем sValue в 4 бита
		for j := 0; j < 4; j++ {
			outputBits[i*4+3-j] = (sValue >> j) & 1
		}
	}
	return outputBits, nil
}

// PermuteBitsToBits применяет перестановку и возвращает срез битов
func PermuteBitsToBits(value []byte, pBlock []int, flag bool, startBitNumber int) ([]int, error) {
	totalInputBits := len(value) * 8
	totalOutputBits := len(pBlock)
	outputBits := make([]int, totalOutputBits)

	for i, pIndex := range pBlock {
		adjustedIndex := pIndex - startBitNumber

		if adjustedIndex < 0 || adjustedIndex >= totalInputBits {
			return nil, errors.New("bit index out of range in permutation block")
		}

		var actualBitIndex int
		if flag {
			actualBitIndex = adjustedIndex
		} else {
			actualBitIndex = totalInputBits - 1 - adjustedIndex
		}

		bytePosition := actualBitIndex / 8
		bitPosition := 7 - (actualBitIndex % 8)

		bitValue := int((value[bytePosition] >> uint(bitPosition)) & 1)
		outputBits[i] = bitValue
	}

	return outputBits, nil
}

// EncryptAsync выполняет асинхронное шифрование данных
func (des *DES) EncryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		encryptedData, err := des.Encrypt(data)
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
func (des *DES) DecryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		decryptedData, err := des.Decrypt(data)
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
