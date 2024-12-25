/*
main.go  --  This file is part of verify_some_rootfs_files_during_initramfs.

# Copyright (C) 2024 Similaduo

verify_some_rootfs_files_during_initramfs is free software: you can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

verify_some_rootfs_files_during_initramfs is distributed in the hope that it
will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
*/
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const chunkSize = 4096

func handleSigint(sig os.Signal) {}

func askUser() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Seems like some of your rootfs file is corrupt, do you want to continue?")
	fmt.Println("NOTE: For security reasons, the emergency shell is disabled in many distros right now.")
	fmt.Println("So the only choice you can type is 'y' or 'Y' if you still want to boot via the rootfs located in your initial hard drive.")
	fmt.Println("Of course, if you think the reason of the corruption of some rootfs file is due to some security issues, please do not boot from the existing rootfs but boot from a bootable usb drive to check your rootfs files.")
	fmt.Println("You can press ctrl+alt+del to reboot you computer.\nNow typing your choice ('y' or 'Y' if you still want to continue) or press ctrl+alt+del to reboot")

	for {
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(response)
		if response == "y" || response == "Y" {
			os.Exit(0)
		} else {
			fmt.Println("Invalid choice. Please input 'y' or 'Y' to continue.")
		}
	}
}

func readFileChunked(filePath string, processChunk func([]byte) error) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", filePath, err)
	}
	defer file.Close()

	buffer := make([]byte, chunkSize)
	for {
		bytesRead, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file %s: %v", filePath, err)
		}
		if bytesRead == 0 {
			break
		}
		if err := processChunk(buffer[:bytesRead]); err != nil {
			return err
		}
	}
	return nil
}

func processChunk(mdctx hash.Hash) func([]byte) error {
	return func(chunk []byte) error {
		_, err := mdctx.Write(chunk)
		if err != nil {
			return fmt.Errorf("error updating digest: %v", err)
		}
		return nil
	}
}

func verifySignature(filePath string, sigPath string, pubkey interface{}) error {
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("error reading signature file %s: %v", sigPath, err)
	}

	mdctx := sha256.New()

	err = readFileChunked(filePath, processChunk(mdctx))
	if err != nil {
		return err
	}

	digest := mdctx.Sum(nil)

	switch pubkey := pubkey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pubkey, digest, sig) {
			return fmt.Errorf("ECDSA signature verification failed for %s", filePath)
		}
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, digest, sig)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed for %s: %v", filePath, err)
		}
	default:
		return fmt.Errorf("unsupported public key type for %s", filePath)
	}

	return nil
}

func loadPublicKey(pubKeyPath string) (interface{}, error) {
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error opening public key file %s: %v", pubKeyPath, err)
	}

	block, _ := pem.Decode(pubKeyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error reading public key from %s: %v", pubKeyPath, err)
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		for sig := range sigChan {
			handleSigint(sig)
		}
	}()

	if len(os.Args) != 6 {
		log.Fatalf("Usage: %s <pub_key_path> <filelist_path> <filelist_sig_path> <root_path> <verify_dir>\n", os.Args[0])
	}

	pubKeyPath := os.Args[1]
	filelistPath := os.Args[2]
	filelistSigPath := os.Args[3]
	rootPath := os.Args[4]
	verifyDir := os.Args[5]

	pubkey, err := loadPublicKey(pubKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	err = verifySignature(filelistPath, filelistSigPath, pubkey)
	if err != nil {
		log.Fatal(err)
	}

	filelistFile, err := os.Open(filelistPath)
	if err != nil {
		log.Fatalf("error opening filelist %s: %v", filelistPath, err)
	}
	defer filelistFile.Close()

	scanner := bufio.NewScanner(filelistFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			num := parts[0]
			path := parts[1]

			filePath := filepath.Join(rootPath, path)
			sigPath := filepath.Join(verifyDir, num+".sig")

			fmt.Printf("Verifying: %s\n", filePath)
			err = verifySignature(filePath, sigPath, pubkey)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading filelist %s: %v", filelistPath, err)
	}

	fmt.Println("Verification process completed successfully.")
}
