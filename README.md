# go-argon2id
Argon2id wrapper implementation over official Go argon2 package for convenience

## Installation
```bash
go get -u github.com/notEpsilon/go-argon2id
```

## Usage
```go
import (
  "github.com/notEpsilon/go-argon2id"
)

hasher := argon2id.NewArgon2Id()

// hash password
hash, err := hasher.Hash("MyPassword123")
if err != nil {
  panic(err)
}

// compare password with a hash
match, err := hasher.Compare("MyPassword123", hash)
if err != nil {
  panic(err)
}

// ...
```
