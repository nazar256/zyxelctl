package router

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestEncryptEnvelopeInteroperatesWithRSAAndAES(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	envelope, aesKey, err := EncryptEnvelope([]byte(`{"message":"hello"}`), publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(aesKey) != 32 {
		t.Fatalf("AES key length = %d, want 32", len(aesKey))
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(envelope.Key)
	if err != nil {
		t.Fatal(err)
	}
	transportedKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
	if err != nil {
		t.Fatal(err)
	}
	wantTransported := base64.StdEncoding.EncodeToString(aesKey)
	if string(transportedKey) != wantTransported {
		t.Fatalf("transported key = %q, want base64 AES key", transportedKey)
	}
	plaintext, err := DecryptEnvelope(envelope, aesKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != `{"message":"hello"}` {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestEncryptEnvelopeAcceptsPKCS1PublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})
	if _, _, err := EncryptEnvelope([]byte("payload"), publicPEM); err != nil {
		t.Fatalf("EncryptEnvelope() error = %v", err)
	}
}

func TestEncryptWithKeyOmitsRSAKeyAndRoundTrips(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	envelope, err := EncryptWithKey([]byte("payload"), key)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Key != "" {
		t.Fatalf("Key = %q, want empty", envelope.Key)
	}
	plaintext, err := DecryptEnvelope(envelope, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "payload" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestDecryptEnvelopeRejectsMalformedPadding(t *testing.T) {
	key := make([]byte, 32)
	envelope := Envelope{
		Content: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		IV:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	if _, err := DecryptEnvelope(envelope, key); err == nil {
		t.Fatal("DecryptEnvelope() error = nil, want malformed padding error")
	}
}

func TestOptionalJSONAcceptsEmptySuccess(t *testing.T) {
	value, err := ParseOptionalJSON(nil, 204)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("value = %#v, want nil", value)
	}
}

func TestOptionalJSONRejectsEmptyFailureAndMalformedJSON(t *testing.T) {
	if _, err := ParseOptionalJSON(nil, 500); err == nil {
		t.Fatal("empty HTTP 500 response accepted")
	}
	if _, err := ParseOptionalJSON([]byte("not-json"), 200); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}

func TestOptionalJSONDecodesObject(t *testing.T) {
	value, err := ParseOptionalJSON([]byte(`{"result":"ZCFG_SUCCESS"}`), 200)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"result": "ZCFG_SUCCESS"}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("value = %#v, want %#v", value, want)
	}
}
