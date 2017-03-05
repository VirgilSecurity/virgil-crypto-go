# virgil-crypto-go
Crypto implementation which uses wrapper for c++ crypto library

##Usage

* Place generated virgil_crypto_go.go and all dependencies in this folder
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
