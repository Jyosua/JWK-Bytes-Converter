package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	encodeOutput = kingpin.Flag("base64", "Encode the output in base64.").Short('e').Bool()
	jwkInput     = kingpin.Flag("JWK", "The JWK to convert").String()
	bytesInput   = kingpin.Flag("bytes", "The private key bytes to parse").HexBytes()
)

func main() {
	kingpin.Version("0.0.1")
	kingpin.Parse()
	if *jwkInput != "" && len(*bytesInput) != 0 {
		fmt.Println("You cannot use both JWK and bytes flags at the same time.")
		return
	}
	if *jwkInput != "" {
		jwk, err := ConvertJson(*jwkInput)
		if err != nil {
			return
		}
		keyBytes := ConvertJWKToBytes(jwk)
		PrintBytes(keyBytes)
		return
	}
	if len(*bytesInput) != 0 {
		PrintJWK(CreateJWK(*bytesInput))
		return
	}
}

func ConvertJson(jsonInput string) (jwk JWK, err error) {
	if err = json.Unmarshal([]byte(jsonInput), &jwk); err != nil {
		fmt.Println("Provided JSON was unparsable.")
	}
	return
}

func ConvertJWKToBytes(jwk JWK) []byte {
	d, _ := base64.RawURLEncoding.DecodeString(jwk.D)
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	return append(d, x...)
}

func PrintBytes(bytes []byte) {
	fmt.Print("Output: ")
	if *encodeOutput {
		fmt.Println(base64.RawURLEncoding.EncodeToString(bytes))
	} else {
		fmt.Println(hex.EncodeToString(bytes))
	}
}

func CreateJWK(bytes []byte) (jwk JWK) {
	privateKeyBytes := bytes[:32]
	publicKeyBytes := bytes[32:]

	return JWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(publicKeyBytes),
		D:   base64.RawURLEncoding.EncodeToString(privateKeyBytes),
		Use: "sig",
		KID: "",
	}
}

func PrintJWK(jwk JWK) {
	fmt.Print("Output: ")
	result, _ := json.Marshal(jwk)
	if *encodeOutput {
		fmt.Println(base64.RawURLEncoding.EncodeToString(result))
	} else {
		fmt.Println(string(result))
	}
}

type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d"`
	Use string `json:"use"`
	KID string `json:"kid"`
}
