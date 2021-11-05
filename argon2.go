package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type HashParams struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

type Hash struct {
	Salt []byte
	Hash []byte
}

var (
	ErrInvalidHash           = errors.New("Hash cannot be decoded")
	ErrIncompatibleAlgorithm = errors.New("Hash uses incompatible algorithm")
	ErrIncompatibleVersion   = errors.New("Hash uses incompatible argon2 version")
)

func HashPassword(params *HashParams, password []byte) (Hash, error) {
	salt := make([]byte, params.SaltLength)
	_, err := rand.Read(salt)

	if err != nil {
		return Hash{}, err
	}

	hash := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLength)

	return Hash{
		Salt: salt,
		Hash: hash,
	}, nil
}

func FormatHash(params *HashParams, hash *Hash) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(hash.Salt),
		base64.RawStdEncoding.EncodeToString(hash.Hash),
	)
}

func ValidateEncodedHash(password []byte, encoded string) (bool, error) {
	hash, params, err := DecodeHash(encoded)
	if err != nil {
		return false, err
	}

	return ValidateHash(params, password, &hash)
}

func ValidateHash(params *HashParams, password []byte, hash *Hash) (bool, error) {
	passwordHash := argon2.IDKey(password, hash.Salt, params.Time, params.Memory, params.Threads, params.KeyLength)

	return subtle.ConstantTimeCompare(hash.Hash, passwordHash) == 1, nil
}

func DecodeHash(encoded string) (Hash, *HashParams, error) {
	hash := Hash{}

	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || len(fields[0]) != 0 {
		return hash, nil, ErrInvalidHash
	}

	if fields[1] != "argon2id" {
		return hash, nil, ErrIncompatibleAlgorithm
	}

	var version int
	_, err := fmt.Sscanf(fields[2], "v=%d", &version)
	if err != nil {
		return hash, nil, err
	}
	if version != argon2.Version {
		return hash, nil, ErrIncompatibleVersion
	}

	params := &HashParams{}

	_, err = fmt.Sscanf(fields[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Threads)
	if err != nil {
		return hash, nil, err
	}

	decoder := base64.RawStdEncoding.Strict()

	salt, err := decoder.DecodeString(fields[4])
	if err != nil {
		return hash, nil, err
	}
	hash.Salt = salt
	params.SaltLength = uint32(len(salt))

	hashVal, err := decoder.DecodeString(fields[5])
	if err != nil {
		return hash, nil, err
	}
	hash.Hash = hashVal
	params.KeyLength = uint32(len(hashVal))

	return hash, params, nil
}
