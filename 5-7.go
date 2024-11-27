package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

var cipherModes = map[string]CipherMode{
	"ECB":         ECB,
	"CBC":         CBC,
	"PCBC":        PCBC,
	"CFB":         CFB,
	"OFB":         OFB,
	"CTR":         CTR,
	"RandomDelta": RandomDelta,
}

var paddingModes = map[string]PaddingMode{
	"Zeros":    Zeros,
	"ANSIX923": ANSIX923,
	"PKCS7":    PKCS7,
	"ISO10126": ISO10126,
}

func main() {
	// Определяем флаги
	cipherFlag := flag.String("mode", "CBC", "Режим шифрования: ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta")
	paddingFlag := flag.String("padding", "PKCS7", "Режим набивки: Zeros, ANSIX923, PKCS7, ISO10126")
	algorithmFlag := flag.String("algorithm", "DES", "Алгоритм шифрования: DES или DEAL")
	keyFlag := flag.String("key", "", "Ключ шифрования в шестнадцатеричном формате (например, \"0011223344556677\")")
	ivFlag := flag.String("iv", "", "Вектор инициализации в шестнадцатеричном формате (например, \"8899aabbccddeeff\")")
	inputFile := flag.String("input", "", "Путь к входному файлу")
	outputFile := flag.String("output", "", "Путь к выходному файлу")
	encryptFlag := flag.Bool("encrypt", true, "Шифровать (true) или дешифровать (false)")

	flag.Parse()

	// Проверяем, что задан входной и выходной файлы
	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Необходимо указать входной и выходной файлы.")
		flag.Usage()
		os.Exit(1)
	}

	// Получаем режим шифрования
	cipherMode, ok := cipherModes[*cipherFlag]
	if !ok {
		fmt.Printf("Неверный режим шифрования: %s\n", *cipherFlag)
		flag.Usage()
		os.Exit(1)
	}

	// Получаем режим набивки
	paddingMode, ok := paddingModes[*paddingFlag]
	if !ok {
		fmt.Printf("Неверный режим набивки: %s\n", *paddingFlag)
		flag.Usage()
		os.Exit(1)
	}

	// Выбираем алгоритм шифрования
	var cipher SymmetricAlgorithm
	var blockSize int
	var err error

	switch *algorithmFlag {
	case "DES":
		cipher, err = NewDES()
		if err != nil {
			panic(err)
		}
		blockSize = 8
	case "DEAL":
		cipher, err = NewDEAL()
		if err != nil {
			panic(err)
		}
		blockSize = 16
	default:
		fmt.Printf("Неверный алгоритм шифрования: %s\n", *algorithmFlag)
		flag.Usage()
		os.Exit(1)
	}

	// Получаем ключ
	if *keyFlag == "" {
		fmt.Println("Необходимо указать ключ шифрования через параметр -key.")
		flag.Usage()
		os.Exit(1)
	}

	key, err := hex.DecodeString(*keyFlag)
	if err != nil {
		fmt.Printf("Неверный формат ключа: %v\n", err)
		os.Exit(1)
	}

	// Проверяем длину ключа
	expectedKeyLength := blockSize // Для DES это 8 байт, для DEAL может быть 16 байт
	if len(key) != expectedKeyLength {
		fmt.Printf("Ключ должен быть длиной %d байт (hex string длиной %d символов)\n", expectedKeyLength, expectedKeyLength*2)
		os.Exit(1)
	}

	// Устанавливаем ключ в шифр
	err = cipher.SetKey(key)
	if err != nil {
		fmt.Printf("Ошибка при установке ключа: %v\n", err)
		os.Exit(1)
	}

	// Получаем IV, если требуется
	var iv []byte
	if cipherMode != ECB {
		if *ivFlag == "" {
			fmt.Println("Необходимо указать вектор инициализации (IV) через параметр -iv.")
			flag.Usage()
			os.Exit(1)
		}
		iv, err = hex.DecodeString(*ivFlag)
		if err != nil {
			fmt.Printf("Неверный формат IV: %v\n", err)
			os.Exit(1)
		}

		// Проверяем длину IV
		if len(iv) != blockSize {
			fmt.Printf("IV должен быть длиной %d байт (hex string длиной %d символов)\n", blockSize, blockSize*2)
			os.Exit(1)
		}
	}

	// Создаем контекст шифрования
	cryptoContext, err := NewCryptoSymmetricContext(
		key,
		cipher,
		cipherMode,
		paddingMode,
		iv,
		blockSize,
	)
	if err != nil {
		panic(err)
	}

	// Выполняем шифрование или дешифрование файла
	var errChan <-chan error
	if *encryptFlag {
		errChan = cryptoContext.EncryptFileAsync(*inputFile, *outputFile)
	} else {
		errChan = cryptoContext.DecryptFileAsync(*inputFile, *outputFile)
	}
	// Ожидаем завершения операции
	if err := <-errChan; err != nil {
		fmt.Printf("Ошибка при обработке файла: %v\n", err)
		os.Exit(1)
	}

	if *encryptFlag {
		fmt.Println("Шифрование завершено успешно.")
	} else {
		fmt.Println("Дешифрование завершено успешно.")
	}
}

func generateRandomBytes(size int) []byte {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		panic("Не удалось сгенерировать случайные данные")
	}
	return data
}
