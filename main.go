package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/pedroalbanese/gogost/gost34112012256"
)

// ============================================================================
// Параметры эллиптической кривой (ГОСТ Р 34.10-2012, 256 бит, Набор параметров A)
// ============================================================================
var (
	// p - простое число, модуль поля
	P = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97")
	// a, b - коэффициенты уравнения кривой y^2 = x^3 + ax + b (mod p)
	A = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94")
	B = hexToBigInt("00000000000000000000000000000000000000000000000000000000000000A6")
	// q - порядок группы точек кривой
	Q = hexToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893")
	// x, y - координаты базовой точки P (генератора группы)
	Gx = hexToBigInt("0000000000000000000000000000000000000000000000000000000000000001")
	Gy = hexToBigInt("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14")
	G  = Point{X: Gx, Y: Gy}
)

// Point представляет точку на эллиптической кривой
type Point struct {
	X, Y *big.Int
}

// ============================================================================
// Вспомогательные математические функции
// ============================================================================

func hexToBigInt(h string) *big.Int {
	b, _ := new(big.Int).SetString(h, 16)
	return b
}

func modInverse(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

// pointAdd выполняет сложение двух точек на эллиптической кривой
func pointAdd(p1, p2 Point) Point {
	// Обработка точки на бесконечности (нулевой точки)
	if p1.X == nil && p1.Y == nil {
		return p2
	}
	if p2.X == nil && p2.Y == nil {
		return p1
	}

	// Проверка на противоположные точки: p1 == -p2
	negY := new(big.Int).Sub(P, p2.Y)
	negY.Mod(negY, P)
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(negY) == 0 {
		return Point{nil, nil} // Возвращаем точку на бесконечности
	}

	var lambda *big.Int
	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 {
		// Удвоение точки (point doubling)
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Exp(p1.X, big.NewInt(2), P))
		num.Add(num, A).Mod(num, P)
		den := new(big.Int)
		den = den.Mul(big.NewInt(2), p1.Y).Mod(den, P)
		invDen := modInverse(den, P)
		lambda = new(big.Int).Mul(num, invDen).Mod(lambda, P)
	} else {
		// Сложение различных точек
		num := new(big.Int)
		den := new(big.Int)
		num = num.Sub(p2.Y, p1.Y).Mod(num, P)
		den = den.Sub(p2.X, p1.X).Mod(den, P)
		invDen := modInverse(den, P)
		lambda = new(big.Int).Mul(num, invDen).Mod(lambda, P)
	}

	// Вычисление координат новой точки
	x3 := new(big.Int).Sub(new(big.Int).Exp(lambda, big.NewInt(2), P), p1.X)
	x3.Sub(x3, p2.X).Mod(x3, P)

	y3 := new(big.Int)
	y3 = y3.Sub(p1.X, x3).Mod(y3, P)
	y3.Mul(y3, lambda).Mod(y3, P)
	y3.Sub(y3, p1.Y).Mod(y3, P)

	return Point{X: x3, Y: y3}
}

// scalarMult выполняет скалярное умножение точки k * P (алгоритм удвоения и сложения)
func scalarMult(k *big.Int, p Point) Point {
	res := Point{nil, nil} // Точка на бесконечности
	addend := p
	kCopy := new(big.Int).Set(k)

	for kCopy.Sign() > 0 {
		if kCopy.Bit(0) == 1 {
			res = pointAdd(res, addend)
		}
		addend = pointAdd(addend, addend) // Удвоение
		kCopy.Rsh(kCopy, 1)
	}
	return res
}

// ============================================================================
// Работа с хэш-функцией и преобразованием данных
// ============================================================================

// hashMessage вычисляет хэш сообщения по ГОСТ Р 34.11-2012 и преобразует его в целое число e
func hashMessage(msg []byte) *big.Int {
	h := gost34112012256.New()
	h.Write(msg)
	hashBytes := h.Sum(nil)

	e := new(big.Int).SetBytes(hashBytes)
	e.Mod(e, Q)
	if e.Sign() == 0 {
		e.SetInt64(1) // По стандарту, если e = 0, то e = 1
	}
	return e
}

func intToBytes(n *big.Int, length int) []byte {
	b := n.Bytes()
	if len(b) > length {
		return b[len(b)-length:] // Обрезаем старшие нули, если вдруг
	}
	res := make([]byte, length)
	copy(res[length-len(b):], b) // Дополняем ведущими нулями слева
	return res
}

func bytesToInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// ============================================================================
// Криптографические операции ГОСТ Р 34.10-2012
// ============================================================================

// GenerateKeyPair генерирует пару ключей (закрытый d и открытый Q = d * G)
func GenerateKeyPair() (*big.Int, Point, error) {
	d, err := rand.Int(rand.Reader, Q)
	if err != nil {
		return nil, Point{}, err
	}
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	pubKey := scalarMult(d, G)
	return d, pubKey, nil
}

// Sign формирует электронную цифровую подпись
func Sign(msg []byte, privKey *big.Int) ([]byte, []byte, error) {
	e := hashMessage(msg)

	for {
		// Генерация случайного числа k (1 < k < q)
		k, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return nil, nil, err
		}
		if k.Sign() == 0 {
			continue
		}

		// Вычисление точки C = k * G
		C := scalarMult(k, G)

		// r = x_C mod q
		r := new(big.Int).Mod(C.X, Q)
		if r.Sign() == 0 {
			continue // Если r = 0, генерируем новое k
		}

		// s = (r * d + k * e) mod q
		s := new(big.Int).Mul(r, privKey)
		ke := new(big.Int).Mul(k, e)
		s.Add(s, ke).Mod(s, Q)

		if s.Sign() == 0 {
			continue // Если s = 0, генерируем новое k
		}

		// Подпись представляет собой пару (r, s)
		return intToBytes(r, 32), intToBytes(s, 32), nil
	}
}

// Verify проверяет электронную цифровую подпись
func Verify(msg []byte, rBytes, sBytes []byte, pubKey Point) bool {
	r := bytesToInt(rBytes)
	s := bytesToInt(sBytes)

	// Проверка условий 0 < r < q и 0 < s < q
	if r.Sign() <= 0 || r.Cmp(Q) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(Q) >= 0 {
		return false
	}

	e := hashMessage(msg)
	v := modInverse(e, Q)

	// z1 = s * v mod q
	z1 := new(big.Int)
	z1 = z1.Mul(s, v).Mod(z1, Q)

	// z2 = -r * v mod q
	negR := new(big.Int).Sub(Q, r)
	z2 := new(big.Int)
	z2 = z2.Mul(negR, v).Mod(z2, Q)

	// Вычисление точки C = z1 * G + z2 * Q
	p1 := scalarMult(z1, G)
	p2 := scalarMult(z2, pubKey)
	C := pointAdd(p1, p2)

	// R = x_C mod q
	R := new(big.Int).Mod(C.X, Q)

	// Подпись верна, если R == r
	return R.Cmp(r) == 0
}

// ============================================================================
// Файловые операции и CLI
// ============================================================================

func saveKeyToFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func loadKeyFromFile(filename string, length int) ([]byte, error) {
	return os.ReadFile(filename)
}

func cmdGenerate(privFile, pubFile string) {
	fmt.Println("Генерация ключевой пары...")
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Ошибка генерации ключей: %v", err)
	}

	privBytes := intToBytes(privKey, 32)
	pubBytes := append(intToBytes(pubKey.X, 32), intToBytes(pubKey.Y, 32)...)

	if err := saveKeyToFile(privFile, privBytes); err != nil {
		log.Fatalf("Ошибка записи закрытого ключа: %v", err)
	}
	if err := saveKeyToFile(pubFile, pubBytes); err != nil {
		log.Fatalf("Ошибка записи открытого ключа: %v", err)
	}

	fmt.Printf("Ключи успешно сохранены:\n")
	fmt.Printf("  Закрытый ключ: %s (32 байта)\n", privFile)
	fmt.Printf("  Открытый ключ: %s (64 байта: X + Y)\n", pubFile)
}

func cmdSign(inFile, privFile, sigFile string) {
	msg, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("Ошибка чтения файла '%s': %v", inFile, err)
	}

	privBytes, err := loadKeyFromFile(privFile, 32)
	if err != nil {
		log.Fatalf("Ошибка чтения закрытого ключа '%s': %v", privFile, err)
	}
	privKey := bytesToInt(privBytes)

	r, s, err := Sign(msg, privKey)
	if err != nil {
		log.Fatalf("Ошибка формирования подписи: %v", err)
	}

	sigBytes := append(r, s...) // Формат подписи: 32 байта r + 32 байта s
	if err := saveKeyToFile(sigFile, sigBytes); err != nil {
		log.Fatalf("Ошибка записи подписи: %v", err)
	}

	fmt.Printf("Подпись успешно сформирована и сохранена в: %s (64 байта)\n", sigFile)
	fmt.Printf("Хэш подписи (r): %s\n", hex.EncodeToString(r))
	fmt.Printf("Хэш подписи (s): %s\n", hex.EncodeToString(s))
}

func cmdVerify(inFile, pubFile, sigFile string) {
	msg, err := os.ReadFile(inFile)
	if err != nil {
		log.Fatalf("Ошибка чтения файла '%s': %v", inFile, err)
	}

	sigBytes, err := loadKeyFromFile(sigFile, 64)
	if err != nil || len(sigBytes) != 64 {
		log.Fatalf("Ошибка чтения подписи '%s' (ожидается 64 байта): %v", sigFile, err)
	}
	rBytes := sigBytes[:32]
	sBytes := sigBytes[32:]

	pubBytes, err := loadKeyFromFile(pubFile, 64)
	if err != nil || len(pubBytes) != 64 {
		log.Fatalf("Ошибка чтения открытого ключа '%s' (ожидается 64 байта): %v", pubFile, err)
	}
	pubKey := Point{
		X: bytesToInt(pubBytes[:32]),
		Y: bytesToInt(pubBytes[32:]),
	}

	isValid := Verify(msg, rBytes, sBytes, pubKey)
	if isValid {
		fmt.Println("Подпись ВЕРНА. Файл не был изменен, автор подтвержден.")
	} else {
		fmt.Println("Подпись НЕВЕРНА. Файл был изменен или ключ не подходит.")
	}
}

func printUsage() {
	fmt.Println("Реализация ГОСТ Р 34.10-2012 (ЭЦП)")
	fmt.Println("Использование:")
	fmt.Println("  go run main.go generate --priv <файл> --pub <файл>")
	fmt.Println("  go run main.go sign --in <файл> --priv <файл> --sig <файл>")
	fmt.Println("  go run main.go verify --in <файл> --pub <файл> --sig <файл>")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "generate":
		genCmd := flag.NewFlagSet("generate", flag.ExitOnError)
		privFile := genCmd.String("priv", "private.key", "Файл для сохранения закрытого ключа")
		pubFile := genCmd.String("pub", "public.key", "Файл для сохранения открытого ключа")
		genCmd.Parse(os.Args[2:])
		cmdGenerate(*privFile, *pubFile)

	case "sign":
		signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
		inFile := signCmd.String("in", "", "Исходный файл для подписания")
		privFile := signCmd.String("priv", "private.key", "Файл закрытого ключа")
		sigFile := signCmd.String("sig", "signature.bin", "Файл для сохранения подписи")
		signCmd.Parse(os.Args[2:])
		if *inFile == "" {
			signCmd.Usage()
			return
		}
		cmdSign(*inFile, *privFile, *sigFile)

	case "verify":
		verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
		inFile := verifyCmd.String("in", "", "Исходный файл для проверки")
		pubFile := verifyCmd.String("pub", "public.key", "Файл открытого ключа")
		sigFile := verifyCmd.String("sig", "signature.bin", "Файл с подписью")
		verifyCmd.Parse(os.Args[2:])
		if *inFile == "" {
			verifyCmd.Usage()
			return
		}
		cmdVerify(*inFile, *pubFile, *sigFile)

	default:
		fmt.Printf("Неизвестная команда: %s\n", cmd)
		printUsage()
	}
}
