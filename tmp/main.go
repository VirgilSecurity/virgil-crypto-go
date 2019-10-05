package main

import (
	"fmt"

	virgil_crypto_go "github.com/VirgilSecurity/virgil-crypto-go"
)

func main() {
	crypto := virgil_crypto_go.NewVirgilCrypto()
	kp, _ := crypto.GenerateKeypair()
	// prepare a message
	dataToSign := []byte("Hello, Bob!")

	// generate signature
	signature, _ := crypto.Sign(dataToSign, kp.PrivateKey())
	fmt.Printf("%X\n", signature)
}
