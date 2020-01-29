package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	encodeOutput      = kingpin.Flag("base64", "Encode the output in base64.").Short('e').Bool()
	interchangeInput  = kingpin.Flag("interchange", "The JWK to convert, but in interchange format.").String()
	jwkInput          = kingpin.Flag("jwk", "The JWK to convert.").String()
	bytesInput        = kingpin.Flag("bytes", "The public or private key bytes to parse.").HexBytes()
	encodedBytesInput = kingpin.Flag("b64bytes", "The public or private key bytes to parse, but encoded in base64.").String()
)

func main() {
	kingpin.Version("0.0.1")
	kingpin.Parse()
	if !GuardInputOkay(*interchangeInput, *jwkInput, *encodedBytesInput, *bytesInput) {
		fmt.Println("You must provide 1 and only 1 input type.")
		return
	}
	if *interchangeInput != "" {
		jwkJSON, _ := base64.RawURLEncoding.DecodeString(*interchangeInput)
		ConvertJWKFromJSONAndPrintBytes(string(jwkJSON))
		return
	}
	if *jwkInput != "" {
		ConvertJWKFromJSONAndPrintBytes(*jwkInput)
		return
	}
	if *encodedBytesInput != "" {
		keyBytes, _ := base64.RawURLEncoding.DecodeString(*encodedBytesInput)
		PrintJWK(CreateJWK(keyBytes))
		return
	}
	if len(*bytesInput) != 0 {
		PrintJWK(CreateJWK(*bytesInput))
		return
	}
}

func GuardInputOkay(interchange, jwk, encodedBytes string, bytes []byte) bool {
	setCount := 0
	if interchange != "" {
		setCount++
	}
	if jwk != "" {
		setCount++
	}
	if encodedBytes != "" {
		setCount++
	}
	if len(bytes) != 0 {
		setCount++
	}
	if setCount != 1 {
		return false
	}
	return true
}

func ConvertJWKFromJSONAndPrintBytes(json string) {
	jwk, err := ConvertJson(json)
	if err != nil {
		return
	}
	keyBytes := ConvertJWKToBytes(jwk)
	PrintBytes(keyBytes)
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
	firstHalf, privateKeyBytes := bytes[:32], bytes[:32]
	secondHalf, publicKeyBytes := bytes[32:], bytes[32:]

	if len(secondHalf) == 0 {
		publicKeyBytes = firstHalf
		privateKeyBytes = secondHalf
	}

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
