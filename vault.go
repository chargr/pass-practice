package main

import (
	"encoding/json"
	"os"
	"slices"
	"uuid"
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
