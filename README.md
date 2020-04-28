# Virgil Crypto Library Go 
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-go.png?branch=v5)](https://travis-ci.org/VirgilSecurity/virgil-crypto-go)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Installation](#installation) | [Usage examples](#usage-examples) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction

Virgil Crypto Library Go is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

## Library purposes

* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* Double Ratchet algorithm support
* **Post quantum algorithms support**: [Round5](https://round5.org/) (ecnryption) and [Falcon](https://falcon-sign.info/) (signature) 
* Crypto for using [Virgil Core SDK](https://github.com/VirgilSecurity/virgil-sdk-go)

## Installation

The package is supported only Linux and Mac OS X. Please make sure [all dependencies](https://github.com/VirgilSecurity/virgil-crypto#build-prerequisites) are installed on your system first.

Set GOPATH variable as described [here](https://github.com/golang/go/wiki/SettingGOPATH)

To install the latest wrapper version run:
```
go get -d -u gopkg.in/virgilsecurity/virgil-crypto-go.v5
```
and then run:
```
cd $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/
make
```
Depending on your choice of crypto implementation you should create crypto instance by calling:

```go
virgil_crypto_go.NewVirgilCrypto()
```
or

```
cryptoimpl.NewVirgilCrypto()
```

## Usage examples

### Generate a key pair

Generate a private key using the default algorithm (EC_X25519):
```go
crypto := virgil_crypto_go.NewVirgilCrypto()
keypair, err := crypto.GenerateKeypair()

```

### Generate and verify a signature

Generate signature and sign data with a private key:
```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// prepare a message
dataToSign := []byte("Hello, Bob!")

// generate signature
signature, err := crypto.Sign(dataToSign, privateKey)
```

Verify a signature with a public key:
```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// verify signature using Alice's Card
err := crypto.VerifySignature(dataToSign, signature, alicePublicKey)

```
### Encrypt and decrypt data

Encrypt data with a public key:

```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// prepare a message
message := []byte("Hello, Bob!")

// encrypt the message
encrypted, err := crypto.Encrypt(message, bobPublicKey)

```

Decrypt the encrypted data with a private key:

```go
crypto := virgil_crypto_go.NewVirgilCrypto()

// decrypt the encrypted data using a private key
decrypted, err := crypto.Decrypt(encryptedMessage, bobPrivateKey)
```

### Import and export keys

Export keys:

```
// generate a new Key
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		//handle error
	}
	// export the private key
	privateKeyData, err := crypto.ExportPrivateKey(keypair.PrivateKey(), "<YOUR_PASSWORD>")
	if err != nil {
		//handle error
	}
	//convert to readable format
	privateKeyStr := base64.StdEncoding.EncodeToString(privateKeyData)
  
  // export the public key
	publicKeyData, err := crypto.ExportPublicKey(keypair.PublicKey())
	if err != nil {
		//handle error
	}
	//convert to readable format
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKeyData)
```

Import keys:

```
privateKeyStr := "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBtfBoM7VfmWPlvyHuGWvMSAgIZ6zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECwaKJKWFNn3OMVoUXEcmqcEQMZ+"
	privateKeyData, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		//handle error
	}
	// import a Private key
	privateKey, err := crypto.ImportPrivateKey(privateKeyData, "YOUR_PASSWORD")
	if err != nil {
		//handle error
	}

//-----------------------------------------------------

publicKeyStr := "MCowBQYDK2VwAyEA9IVUzsQENtRVzhzraTiEZZy7YLq5LDQOXGQG/q0t0kE="
	publicKeyData, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		//handle error
	}
	// import a Public key
	publicKey, err := crypto.ImportPublicKey(publicKeyData)
	if err != nil {
		//handle error
	}
```


## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [Developer Documentation](https://developer.virgilsecurity.com/docs/)

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
