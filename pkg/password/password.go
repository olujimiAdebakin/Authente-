package password

import (
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"os"
)

// Hash hashes a password using bcrypt
func Hash(password string) (string, error) {
		cost := bcrypt.DefaultCost 
	if c := os.Getenv("BCRYPT_COST"); c != "" {
		if parsed, err := strconv.Atoi(c); err == nil {
			cost = parsed
		}
	}

	 hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Check verifies a password against a hash
func Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}