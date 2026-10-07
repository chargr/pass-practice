package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"uuid"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type PracticeVault struct {
	Hashes []*PasswordHash `json:"hashes"`
}

func NewPracticeVault() *PracticeVault {
	var hashes []*PasswordHash
	return &PracticeVault{hashes}
}

func (v *PracticeVault) Save(vaultpath string) error {
	data, _ := json.MarshalIndent(v, "", "\t")
	err := os.WriteFile(vaultpath, data, 0600)
	if err != nil {
		return err
	}
	return nil
}

func LoadVault(path string) *PracticeVault {
	var v PracticeVault
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &v)
	return &v
}

func (v *PracticeVault) Add(hash *PasswordHash) {
	v.Hashes = append(v.Hashes, hash)
}

func (v *PracticeVault) Remove(id string) {
	v.Hashes = slices.DeleteFunc(v.Hashes, func(h *PasswordHash) bool { return h.UUID.String() == id })
}

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

func command_add(vault *PracticeVault, label string) error {

	//vault := NewPracticeVault()

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	ph := NewPasswordHash(label, pw)

	// clear memory and trigger garbage collection
	clear(pw)
	pw = nil

	fmt.Println(ph)

	fmt.Print("Password: ")
	pw, err = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	pwmatch := ph.Check(pw)
	clear(pw)
	pw = nil

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if !pwmatch {
		fmt.Println("Password do not match")
	} else {
		vault.Add(ph)
	}

	return nil
}

func main() {

	var vault *PracticeVault
	var vaultpath string = "practice-vault.json"

	_, err := os.Stat(vaultpath)

	switch {
	case err == nil:
		vault = LoadVault(vaultpath)
	case errors.Is(err, fs.ErrNotExist):
		vault = NewPracticeVault()
	default:
		fmt.Println("Unable to open ", vaultpath)
	}

	root := &cobra.Command{
		Use:   filepath.Base(os.Args[0]),
		Short: "Practice your passphrase",
	}
	/**
	init := &cobra.Command{
		Use:   "init",
		Short: "initialize practice vault",
	}
	*/
	list := &cobra.Command{
		Use:   "list",
		Short: "list configured passphrases",
		Run: func(cmd *cobra.Command, args []string) {
			for _, hash := range vault.Hashes {
				fmt.Println(hash.UUID, hash.Label)
			}
		},
	}

	add := &cobra.Command{
		Use:   "add <label>",
		Short: "add practice phrase",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			label := args[0]
			command_add(vault, label)
			vault.Save(vaultpath)
		},
	}

	practice := &cobra.Command{
		Use:   "practice",
		Short: "practice a password prompt",
		Run: func(cmd *cobra.Command, args []string) {
			hashes := len(vault.Hashes)
			if hashes == 0 {
				fmt.Println("no passwords vault.")
				os.Exit(1)
			}
			selection := vault.Hashes[mrand.IntN(hashes)]

			fmt.Print("Enter Password for ", selection.Label, ":")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()

			check := selection.Check(pw)
			clear(pw)
			pw = nil

			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}

			if check {
				fmt.Println("Password match")
			} else {
				fmt.Println("FAILURE!")
			}
		},
	}

	del := &cobra.Command{
		Use:   "del <uuid>",
		Short: "delete a passphrase by uuid",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := args[0]
			vault.Remove(id)
			vault.Save()
		},
	}

	root.AddCommand(add, list, practice, del)
	// run a default practice if no commands
	root.Run = practice.Run
	root.Execute()
}
