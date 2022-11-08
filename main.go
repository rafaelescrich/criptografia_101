package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/sha3"
)

// GerarHash
func GerarHash() {

	// cryptographic hash
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	s := "Reunião virtual Direito Digital OAB - SC 2022"
	fmt.Println("Texto a ser hasheado: ", s)

	md5 := md5.Sum([]byte(s))
	sha2_256 := sha256.Sum256([]byte(s))
	sha3_256 := sha3.Sum256([]byte(s))

	fmt.Printf("MD5: %x\n", md5)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Printf("SHA2-256: %x\n", sha2_256)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Printf("SHA3-256: %x\n", sha3_256)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")

}

// ---------------------------------------------------------------------
// Criptografia Simétrica
func CifrarSimetrica() {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := []byte("ReuniaoVirtualDireitoDigital2022")
	plaintext := []byte("Este é o texto plano a ser cifrado com a chave simétrica")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := []byte("CryptoFriday")

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("Texto cifrado com chave simétrica: %x\n", ciphertext)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func DecifrarSimetrica() {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := []byte("ReuniaoVirtualDireitoDigital2022")
	ciphertext, _ := hex.DecodeString("0e048c45560b7a7beffa67c2903a6b0ed4604eebaac4edd9494deee297f7d489193701a68edc92ac02a0fdea4224e3920f5e36560c816bac82b454c4ab1107f69771369cfab9a5767a09")

	nonce := []byte("CryptoFriday")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Texto decifrado com chave simétrica: %s\n", string(plaintext))
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

// --------------------------------------------------------------------------------------
// Criptografia Assimétrica
// RSA

const (
	rsaKeySize = 2048
	hash       = crypto.SHA256
)

type keypair struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

var parChavesAlice keypair
var parChavesBob keypair
var ciphertext, signedMessage []byte
var msgHashed [32]byte

func GerarParDeChavesAlice() {
	var err error
	parChavesAlice.priv, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}
	parChavesAlice.pub = &parChavesAlice.priv.PublicKey

	fmt.Printf("Chave Privada Alice: %x\n", parChavesAlice.priv)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Printf("Chave Pública Alice: %x\n", parChavesAlice.pub)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")

}

func GerarParDeChavesBob() {
	var err error
	parChavesBob.priv, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}
	parChavesBob.pub = &parChavesAlice.priv.PublicKey

	fmt.Printf("Chave Privada Bob: %x\n", parChavesAlice.priv)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Printf("Chave Pública Bob: %x\n", parChavesAlice.pub)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func CifrarAssimetrica() {

	var err error

	secretMessage := []byte("Esta é a mensagem a ser cifrada no evento de Direito Digital da OAB - SC")
	label := []byte("talk")

	ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, parChavesBob.pub, secretMessage, label)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Texto cifrado com chave pública de Bob: %x\n", ciphertext)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func DecifrarAssimetrica() {

	label := []byte("talk")

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parChavesBob.priv, ciphertext, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	fmt.Printf("Texto decifrado com chave privada de Bob: %s\n", string(plaintext))
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func AssinarAssimetrica() {
	var err error
	message := []byte("Esta é a mensagem a ser assinada no evento de Direito Digital da OAB - SC")

	msgHashed = sha256.Sum256(message)

	signedMessage, err = rsa.SignPKCS1v15(rand.Reader, parChavesAlice.priv, hash, msgHashed[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("Mensagem assinada pela chave privada da Alice: %x\n", signedMessage)
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func VerificarAssinaturaAssimetrica() {

	err := rsa.VerifyPKCS1v15(parChavesAlice.pub, hash, msgHashed[:], signedMessage)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
	}

	fmt.Printf("Mensagem Verificada usando a chave pública da Alice!\n")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
	fmt.Println("-------------------------------------------------------------------------------")
}

func main() {

	// Hash criptográfico
	GerarHash()

	// Criptografia Simétrica
	CifrarSimetrica()
	DecifrarSimetrica()

	// Criptografia Assimétrica
	GerarParDeChavesAlice()
	GerarParDeChavesBob()
	CifrarAssimetrica()
	DecifrarAssimetrica()
	AssinarAssimetrica()
	VerificarAssinaturaAssimetrica()

}
