package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	osFile "de_wallet/internal/localFile"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	walletsStorage = "./wallets"
	filename       = "encryptedData.bin"
	encryptionKey  = "encryptionkeytonewcipher32bytes!"
)

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-ctx.Done()
		log.Println("Shutdown signal received")
	}()

	localFile := osFile.NewLocalFile(filename)
	err := app(ctx, localFile)
	if err != nil {
		log.Println(err)
	}
}

func app(ctx context.Context, localFile *osFile.FileLocal) error {
	ctxApp, cancel := context.WithCancel(ctx)

	var walletPassword string
	anySavedWallets, err := walletExists()
	if err != nil {
		return fmt.Errorf("check wallets %w", err)
	}

	if anySavedWallets {
		fmt.Println("Enter your wallet password: ")
		_, err := fmt.Scanf("%s", &walletPassword)
		if err != nil {
			return fmt.Errorf("scan existing password %w", err)
		}

		newlinePassword := make(chan []byte)
		doneCh := make(chan bool)
		go func(newlinePassword chan []byte, doneCh chan bool) {
			errRead := localFile.Read(ctxApp, newlinePassword, doneCh)
			if err == nil {
				err = errRead
				cancel()
			} else if errRead != nil {
				fmt.Errorf("read password from file %w", errRead)
				cancel()
			}
		}(newlinePassword, doneCh)

		for {
			select {
			case newString := <-newlinePassword:
				decodedData, err := decodeData(newString)
				if err != nil {
					return fmt.Errorf("decode data %w", err)
				}

				hashedPassword, err := hashPassword(walletPassword)
				if err != nil {
					return fmt.Errorf("hash password %w", err)
				}

				if bytes.Compare(decodedData, hashedPassword) == 0 {
					fmt.Println("wallet unlocked")
					return nil
				} else {
					continue
				}

			case <-doneCh:
				fmt.Println("check your password again, no wallet found")
				return nil
			case <-ctx.Done():
				return nil
			}
		}

	}

	fmt.Println("Enter a new wallet password: ")
	_, err = fmt.Scanf("%s", &walletPassword)
	if err != nil {
		return fmt.Errorf("scan new password %w", err)
	}

	hashedPassword, err := hashPassword(walletPassword)
	if err != nil {
		return fmt.Errorf("hash password %w", err)
	}

	encodedPassword, err := encodeData(hashedPassword)
	if err != nil {
		return fmt.Errorf("encrypt password %w", err)
	}

	err = localFile.Write(ctxApp, encodedPassword)
	if err != nil {
		return fmt.Errorf("write to file %w", err)
	}

	walletKey, err := getWalletKey()
	if err != nil {
		return fmt.Errorf("get wallet key %w", err)
	}

	err = saveWallet(walletKey)
	if err != nil {
		return fmt.Errorf("save wallet %w", err)
	}

	fmt.Println("wallet created")
	return nil
}

func walletExists() (bool, error) {
	f, err := os.Open(walletsStorage)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err != io.EOF {
		return true, nil
	}
	return false, nil
}

func getWalletKey() (string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("ethereum client connection %w", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyString := hexutil.Encode(privateKeyBytes)[2:]
	return privateKeyString, nil
}

func saveWallet(walletKey string) error {
	ks := keystore.NewKeyStore(walletsStorage, keystore.StandardScryptN, keystore.StandardScryptP)
	_, err := ks.NewAccount(walletKey)
	if err != nil {
		return fmt.Errorf("save wallet to keystores %w", err)
	}

	return nil
}

func hashPassword(password string) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("write hash %w", err)
	}

	hashBytes := hash.Sum(nil)
	return hashBytes, nil
}

func encodeData(password []byte) ([]byte, error) {
	encryptKey := []byte(encryptionKey)
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("cipher block creation %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, password, nil)
	return cipherText, nil
}

func decodeData(cipherText []byte) ([]byte, error) {
	encryptKey := []byte(encryptionKey)
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, fmt.Errorf("cipher block creation %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM %w", err)
	}

	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	decodedPassword, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt file %w", err)
	}
	return decodedPassword, nil
}
