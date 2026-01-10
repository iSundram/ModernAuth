package utils

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "SecurePassword123!"

	hash, err := HashPassword(password, nil)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify the hash format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash should start with $argon2id$, got: %s", hash)
	}

	// Verify the hash contains expected parts
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Hash should have 6 parts, got: %d", len(parts))
	}
}

func TestHashPasswordWithCustomParams(t *testing.T) {
	password := "TestPassword"
	params := &Argon2Params{
		Memory:      32 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := HashPassword(password, params)
	if err != nil {
		t.Fatalf("HashPassword with custom params failed: %v", err)
	}

	// Verify the hash format contains custom params
	if !strings.Contains(hash, "m=32768,t=2,p=1") {
		t.Errorf("Hash should contain custom params, got: %s", hash)
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "SecurePassword123!"

	hash, err := HashPassword(password, nil)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Test correct password
	match, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Error("VerifyPassword should return true for correct password")
	}

	// Test incorrect password
	match, err = VerifyPassword("WrongPassword", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if match {
		t.Error("VerifyPassword should return false for incorrect password")
	}
}

func TestVerifyPasswordInvalidHash(t *testing.T) {
	testCases := []struct {
		name string
		hash string
	}{
		{"empty hash", ""},
		{"invalid format", "not-a-valid-hash"},
		{"wrong algorithm", "$bcrypt$v=19$m=65536,t=3,p=2$salt$hash"},
		{"missing parts", "$argon2id$v=19$m=65536"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyPassword("password", tc.hash)
			if err == nil {
				t.Errorf("VerifyPassword should fail for %s", tc.name)
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		bytes, err := GenerateRandomBytes(length)
		if err != nil {
			t.Fatalf("GenerateRandomBytes(%d) failed: %v", length, err)
		}
		if len(bytes) != length {
			t.Errorf("GenerateRandomBytes(%d) returned %d bytes", length, len(bytes))
		}
	}

	// Test that two calls produce different results
	b1, _ := GenerateRandomBytes(32)
	b2, _ := GenerateRandomBytes(32)
	if string(b1) == string(b2) {
		t.Error("GenerateRandomBytes should produce unique values")
	}
}

func TestGenerateRandomString(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		str, err := GenerateRandomString(length)
		if err != nil {
			t.Fatalf("GenerateRandomString(%d) failed: %v", length, err)
		}
		if len(str) != length {
			t.Errorf("GenerateRandomString(%d) returned string of length %d", length, len(str))
		}
	}

	// Test that two calls produce different results
	s1, _ := GenerateRandomString(32)
	s2, _ := GenerateRandomString(32)
	if s1 == s2 {
		t.Error("GenerateRandomString should produce unique values")
	}
}

func TestHashToken(t *testing.T) {
	token := "test-token-12345"

	hash1 := HashToken(token)
	hash2 := HashToken(token)

	// Same token should produce same hash
	if hash1 != hash2 {
		t.Error("HashToken should be deterministic")
	}

	// Different tokens should produce different hashes
	hash3 := HashToken("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}

	// Hash should be non-empty
	if len(hash1) == 0 {
		t.Error("HashToken should produce non-empty hash")
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "SecurePassword123!"
	params := DefaultArgon2Params()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashPassword(password, params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	password := "SecurePassword123!"
	hash, _ := HashPassword(password, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyPassword(password, hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}
