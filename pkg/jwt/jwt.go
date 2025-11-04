package jwt



import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Manager is responsible for handling all JWT-related operations:
// generation, signing, and verification.
type Manager struct {
	secretKey string
}

// NewManager constructs the Manager with its required dependency, the secret key.
func NewManager(secretKey string) *Manager {
	return &Manager{secretKey: secretKey}
}

// GenerateToken creates a new JWT access token with the specified user claims.
func (m *Manager) GenerateToken(userID int64, email string, firstName, lastName string) (string, error) {
	// Define the token's payload (claims). 'exp' is the standard expiration time claim.
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"first_name": firstName,  // Change from "name" to "first_name"
            "last_name":  lastName, 
		"name":    firstName + " " + lastName,
		// Token expires 24 hours from creation, represented as a Unix timestamp
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}

	// Create the token object, specifying the signing method (HS256) and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token using the secret key
	return token.SignedString([]byte(m.secretKey))
}

// VerifyToken parses, validates, and returns the claims from a given token string.
func (m *Manager) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token. The keyFunc is called during parsing to get the secret key
	// needed to verify the token's signature.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// SECURITY CHECK: Ensure the token's signing method is what we expect (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		// Return the secret key used for verification
		return []byte(m.secretKey), nil
	})

	if err != nil {
		// Handles errors like 'token is expired' or 'invalid signature'
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract the claims. We assert the claims are in the MapClaims format we used for generation.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims format")
	}

	return claims, nil
}
