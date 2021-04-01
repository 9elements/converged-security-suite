package cbnt

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	//Supported RSA bit length of Intel TXT/CBnT technology
	rsaLen2048 = int(2048)
	rsaLen3072 = int(3072)
)

// GenRSAKey takes the required keylength, two boolean to decide for KM and BPM key and a path
// to create a RSA key pair and writes its public and private keys to files.
func GenRSAKey(len int, password string, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile *os.File) error {
	if len == rsaLen2048 || len == rsaLen3072 {
		key, err := rsa.GenerateKey(rand.Reader, len)
		if err != nil {
			return err
		}
		if err := writePrivKeyToFile(key, kmPrivFile, password); err != nil {
			return err
		}

		if err := writePubKeyToFile(key.Public(), kmPubFile); err != nil {
			return err
		}

		key, err = rsa.GenerateKey(rand.Reader, len)
		if err != nil {
			return err
		}
		if err := writePrivKeyToFile(key, bpmPrivFile, password); err != nil {
			return err
		}

		if err := writePubKeyToFile(key.Public(), bpmPubFile); err != nil {
			return err

		}
		return nil
	}
	return fmt.Errorf("RSA key length must be 2048 or 3084 Bits, but length is: %d", len)
}

// GenECCKey takes the required curve, two boolean to decide for KM and BPM key and a path
// to create a ECDSA key pair and writes its public and private keys to files.
func GenECCKey(curve int, password string, kmPubFile, kmPrivFile, bpmPubFile, bpmPrivFile *os.File) error {
	var ellCurve elliptic.Curve
	switch curve {
	case 224:
		ellCurve = elliptic.P224()
	case 256:
		ellCurve = elliptic.P256()
	default:
		return fmt.Errorf("Selected ECC algorithm not supported")
	}
	key, err := ecdsa.GenerateKey(ellCurve, rand.Reader)
	if err != nil {
		return err
	}

	if err := writePrivKeyToFile(key, kmPrivFile, password); err != nil {
		return err
	}

	if err := writePubKeyToFile(key.Public(), kmPubFile); err != nil {
		return err
	}

	key, err = ecdsa.GenerateKey(ellCurve, rand.Reader)
	if err != nil {
		return err
	}

	if err := writePrivKeyToFile(key, bpmPrivFile, password); err != nil {
		return err
	}

	if err := writePubKeyToFile(key.Public(), bpmPubFile); err != nil {
		return err

	}
	return nil
}

func writePrivKeyToFile(k crypto.PrivateKey, f *os.File, password string) error {
	var key *[]byte
	b, err := x509.MarshalPKCS8PrivateKey(k)
	bpemBlock := &pem.Block{
		Bytes: b,
	}
	bpem := pem.EncodeToMemory(bpemBlock)
	if password != "" {
		encKey, err := encryptPrivFile(&bpem, password)
		if err != nil {
			return err
		}
		key = encKey
	} else {
		key = &bpem
	}

	_, err = f.Write(*key)
	if err != nil {
		return err
	}
	return nil
}

func writePubKeyToFile(k crypto.PublicKey, f *os.File) error {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return err
	}
	bpemBlock := &pem.Block{
		Bytes: b,
	}
	bpem := pem.EncodeToMemory(bpemBlock)
	_, err = f.Write(bpem)
	if err != nil {
		return err
	}
	return nil
}

func encryptPrivFile(data *[]byte, password string) (*[]byte, error) {
	// Hash key to select aes-256 -> using SHA256
	hash := crypto.SHA256.New()
	hash.Write([]byte(password))
	hashPW := hash.Sum(nil)

	bc, err := aes.NewCipher(hashPW)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(bc)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, *data, nil)
	return &ct, nil
}

// DecryptPrivKey takes the encrypted Key as byte slice and the passwort to decrypt the priveate key and returns it with it's type.
func DecryptPrivKey(data []byte, password string) (crypto.PrivateKey, error) {
	var plain []byte
	if password != "" {
		// Set up the crypto stuff
		hash := crypto.SHA256.New()
		hash.Write([]byte(password))
		hashPW := hash.Sum(nil)
		aes, err := aes.NewCipher(hashPW)
		if err != nil {
			return nil, err
		}
		aesGCM, err := cipher.NewGCM(aes)
		if err != nil {
			return nil, err
		}
		nonceSize := aesGCM.NonceSize()

		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		plain, err = aesGCM.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	} else {
		plain = data
	}

	key, err := parsePrivateKey(plain)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	return key, nil
}

// ReadPubKey ready a pem encoded RSA/ECC public key file
func ReadPubKey(path string) (crypto.PublicKey, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "CERTIFICATE") {
			if strings.Contains(block.Type, "RSA") {
				key, err := x509.ParsePKCS1PublicKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("Parsing error in x509.ParsePKCS1PublicKey: %v", err)
				}
				return key, nil
			}
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				if key, ok := key.(crypto.PublicKey); ok {
					return key, nil
				}
				return nil, fmt.Errorf("found unknown public key type (%T) in PKIX wrapping", key)
			}
			return nil, err
		}
		raw = rest
	}
	return nil, fmt.Errorf("failed to parse public key")
}
