# virgil-crypto-go
Crypto implementation which uses wrapper for [c++ crypto library](https://github.com/VirgilSecurity/virgil-crypto)

## Hot to build
The package is supported only Linux and Mac OS X. Please make sure [all dependencis](https://github.com/VirgilSecurity/virgil-crypto#build-prerequisites) are installed on your system first.
1. `go get -d gopkg.in/virgilsecurity/virgil-crypto-go.v4`
2. `cd $GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4`
3. `make`

## Usage
* In your code import gopkg.in/virgilsecurity/virgil-crypto-go.v4
```go
import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"

	crypto "gopkg.in/virgilsecurity/virgil-crypto-go.v4"

)
```
* Replace the default crypto in virgil SDK like this:
```go
  virgilcrypto.DefaultCrypto = &crypto.NativeCrypto{}
```
