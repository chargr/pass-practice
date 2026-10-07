package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"uuid"

	"github.com/spf13/cobra"
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

// return the first matching uuid or label found
func (v *PracticeVault) Find(ref string) *PasswordHash {
	for _, h := range v.Hashes {
		if h.UUID.String() == ref || h.Label == ref {
			return h
		}
	}
	return nil
}

func (v *PracticeVault) RemoveUUID(id uuid.UUID) {
	v.Hashes = slices.DeleteFunc(v.Hashes, func(h *PasswordHash) bool { return h.UUID.Compare(id) == 0 })
}

func readNewPasswordHash(label string) (*PasswordHash, error) {

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return nil, err
	}

	ph := NewPasswordHash(label, pw)

	// clear memory and trigger garbage collection
	clear(pw)
	pw = nil

	fmt.Print("Confirm: ")
	pw, err = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	pwmatch := ph.Check(pw)
	clear(pw)
	pw = nil

	if err != nil {
		return nil, err
	}

	if !pwmatch {
		return nil, fmt.Errorf("Passwords do not match")
	}

	return ph, nil
}

func userDataDir() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support"), nil
	case "windows":
		return os.Getenv("LOCALAPPDATA"), nil
	default:
		return filepath.Join(home, ".local", "share"), nil
	}
}

func main() {

	userdata, err := userDataDir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var vaultpath string = filepath.Join(userdata, "practice-vault.json")
	var vault *PracticeVault

	switch _, err := os.Stat(vaultpath); {
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
			conflict := vault.Find(label)
			if conflict != nil {
				fmt.Println(label, "already exists")
				os.Exit(1)
			}
			hash, err := readNewPasswordHash(label)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			vault.Add(hash)
			vault.Save(vaultpath)
		},
	}

	practice := &cobra.Command{
		Use:   "practice [uuid|label]",
		Short: "practice a password prompt",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			hashes := len(vault.Hashes)
			if hashes == 0 {
				fmt.Println("no passwords vault.")
				os.Exit(1)
			}

			// optional arg for specific practice
			var selection *PasswordHash
			if len(args) >= 1 {
				selection = vault.Find(args[0])
				if selection == nil {
					fmt.Println(args[0], "not found")
					os.Exit(1)
				}
			} else {
				selection = vault.Hashes[mrand.IntN(hashes)]
			}

			fmt.Print("Enter Password for ", selection.Label, ": ")
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
		Use:   "del <uuid|label>",
		Short: "delete a passphrase by uuid or label",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			val := args[0]
			hash := vault.Find(val)
			if hash == nil {
				fmt.Println(val, "not found")
				os.Exit(1)
			}
			vault.RemoveUUID(hash.UUID)
			vault.Save(vaultpath)
		},
	}

	root.AddCommand(add, list, practice, del)
	// run a default practice if no commands
	root.Run = practice.Run
	root.Execute()
}
