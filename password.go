package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"uuid"

	"golang.org/x/crypto/argon2"
)

func generate_hash(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 2, 512*1024, 4, 32)
}

type PasswordHash struct {
	UUID  uuid.UUID `json:"uuid"`
	Label string    `json:"label"`
	Salt  []byte    `json:"salt"`
	Hash  []byte    `json:"hash"`
}

func NewPasswordHash(label string, password []byte) *PasswordHash {
	// create unique hash
	var salt = make([]byte, 16)
	rand.Read(salt)

	var uuid = uuid.New()
	// generate hash
	var hash []byte = generate_hash(password, salt)

	return &PasswordHash{uuid, label, salt, hash}
}

func (ph *PasswordHash) Check(password []byte) bool {
	var hash []byte = generate_hash(password, ph.Salt)

	if subtle.ConstantTimeCompare(hash, ph.Hash) == 0 {
		return false
	}
	return true
}

func (ph *PasswordHash) String() string {
	strsalt := base64.StdEncoding.EncodeToString(ph.Salt)
	strhash := base64.StdEncoding.EncodeToString(ph.Hash)

	return "salt:" + strsalt + " hash:" + strhash
}
