package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidForm = errors.New("provided hash is in an invalid form")
)

type Argon2Hasher interface {
	Hash(string, ...*Options) (string, error)
	Compare(string, string) (bool, error)
	DecodeIntoOptions(string) (Options, []byte, []byte, error)
}

type Options struct {
	Iterations uint32
	Memory     uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

var (
	DefaultOptions = &Options{
		Iterations: 3,
		Memory: 64 * 1024,
		Threads: 4,
		SaltLength: 16,
		KeyLength: 32,
	}
)

type Argon2Id struct{}

var _ Argon2Hasher = (*Argon2Id)(nil)

func (Argon2Id) Hash(plain string, options ...*Options) (string, error) {
	var opts *Options

	if len(options) != 0 {
		opts = options[0]
	} else {
		opts = DefaultOptions
	}

	salt := make([]byte, opts.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(plain), salt, opts.Iterations, opts.Memory, opts.Threads, opts.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	res := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, opts.Memory, opts.Iterations, opts.Threads, b64Salt, b64Key)

	return res, nil
}

func (a Argon2Id) Compare(plain, hash string) (bool, error) {
	opts, key, salt, err := a.DecodeIntoOptions(hash)
	if err != nil {
		return false, err
	}

	otherKey := argon2.IDKey([]byte(plain), salt, opts.Iterations, opts.Memory, opts.Threads, opts.KeyLength)

	if subtle.ConstantTimeEq(int32(opts.KeyLength), int32(len(otherKey))) == 0 {
		return false, nil
	}

	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, nil
	}

	return false, nil
}

func (Argon2Id) DecodeIntoOptions(hash string) (Options, []byte, []byte, error) {
	vals := strings.Split(hash, "$")
	if len(vals) != 6 {
		return Options{}, nil, nil, ErrInvalidForm
	}

	if vals[1] != "argon2id" {
		return Options{}, nil, nil, ErrInvalidForm
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return Options{}, nil, nil, nil
	}

	var mem, iters, threads int
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &mem, &iters, &threads)
	if err != nil {
		return Options{}, nil, nil, err
	}

	rawSalt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return Options{}, nil, nil, err
	}

	rawKey, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return Options{}, nil, nil, err
	}

	return Options{
		Iterations: uint32(iters),
		Memory: uint32(mem),
		Threads: uint8(threads),
		SaltLength: uint32(len(rawSalt)),
		KeyLength: uint32(len(rawKey)),
	}, rawKey, rawSalt, nil
}

func NewArgon2Id() Argon2Id {
	return Argon2Id{}
}
