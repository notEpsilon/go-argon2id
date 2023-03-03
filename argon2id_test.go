package argon2id_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/notEpsilon/go-argon2id"
)

func TestHash(t *testing.T) {
	hashRegex, err := regexp.Compile(`^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if err != nil {
		t.Fatal(err)
	}

	h1, err := argon2id.NewArgon2Id().Hash("P@$$W0RD123@")
	if err != nil {
		t.Fatal(err)
	}

	if !hashRegex.MatchString(h1) {
		t.Errorf("output hash %q is not in correct format", h1)
	}

	h2, err := argon2id.NewArgon2Id().Hash("P@$$W0RD123@")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Compare(h1, h2) == 0 {
		t.Errorf("generated similar hashes and hashes must be unique")
	}
}

func TestCompare(t *testing.T) {
	h1, err := argon2id.NewArgon2Id().Hash("P@$$W0RD123@")
	if err != nil {
		t.Fatal(err)
	}

	match, err := argon2id.NewArgon2Id().Compare("P@$$W0RD123@", h1)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Errorf("expected password and hash to match")
	}

	match, err = argon2id.NewArgon2Id().Compare("badP@$$w0rd", h1)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Errorf("expected password and hash to not match")
	}
}
