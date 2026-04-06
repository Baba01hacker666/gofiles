package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAdminPasswordInitialization(t *testing.T) {
	// 1. Test with ADMIN_PASSWORD_HASH
	t.Run("ADMIN_PASSWORD_HASH", func(t *testing.T) {
		expectedHash := "some_precomputed_hash"
		t.Setenv("ADMIN_PASSWORD_HASH", expectedHash)

		// Reset globals
		adminPasswordHash = nil
		generatedAdminPassword = ""

		initializeConfig()

		if string(adminPasswordHash) != expectedHash {
			t.Errorf("Expected hash %s, got %s", expectedHash, string(adminPasswordHash))
		}
		if generatedAdminPassword != "" {
			t.Errorf("Expected no generated password, got %s", generatedAdminPassword)
		}
	})

	// 2. Test with ADMIN_PASSWORD
	t.Run("ADMIN_PASSWORD", func(t *testing.T) {
		password := "my_secret_password"
		t.Setenv("ADMIN_PASSWORD", password)
		t.Setenv("ADMIN_PASSWORD_HASH", "")

		// Reset globals
		adminPasswordHash = nil
		generatedAdminPassword = ""

		initializeConfig()

		if adminPasswordHash == nil {
			t.Fatal("Expected adminPasswordHash to be set")
		}
		err := bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(password))
		if err != nil {
			t.Errorf("Password hash does not match: %v", err)
		}
		if generatedAdminPassword != "" {
			t.Errorf("Expected no generated password, got %s", generatedAdminPassword)
		}
	})

	// 3. Test auto-generation
	t.Run("Auto-generation", func(t *testing.T) {
		t.Setenv("ADMIN_PASSWORD", "")
		t.Setenv("ADMIN_PASSWORD_HASH", "")

		// Reset globals
		adminPasswordHash = nil
		generatedAdminPassword = ""

		initializeConfig()

		if generatedAdminPassword == "" {
			t.Fatal("Expected generatedAdminPassword to be set")
		}
		if len(generatedAdminPassword) < 32 {
			t.Errorf("Generated password too short: %d", len(generatedAdminPassword))
		}
		if adminPasswordHash == nil {
			t.Fatal("Expected adminPasswordHash to be set")
		}
		err := bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(generatedAdminPassword))
		if err != nil {
			t.Errorf("Generated password hash does not match: %v", err)
		}
	})
}
