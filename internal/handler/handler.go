package handler

import "authentio/internal/service"

// =============================================================================
// Main Handler Aggregator
// =============================================================================

// Handler aggregates all sub-handlers into a single struct.
// 
// Embedding the concrete handlers automatically promotes their methods,
// allowing the router to call methods like `h.GoogleCallback`, `h.Login`, 
// `h.GetProfile`, etc. directly on the main Handler instance.
//
// This pattern provides:
// - Clean organization of related handler groups
// - Single dependency injection point
// - Method promotion without explicit delegation
// - Maintainable and testable structure
type Handler struct {
	*AuthHandler   // Handles authentication endpoints (login, register, OAuth)
	*TwoFAHandler  // Handles two-factor authentication endpoints
	*UserHandler   // Handles user profile management endpoints
}

// =============================================================================
// Constructor
// =============================================================================

// NewHandler builds the complete handler hierarchy from a single AuthService.
// This centralized constructor ensures all handlers share the same service instance
// and provides a single point of initialization for the entire handler layer.
//
// Parameters:
//   - authService: The core service containing business logic for all handlers
//
// Returns:
//   - *Handler: Fully initialized handler aggregator ready for router setup
func NewHandler(authService service.AuthService) *Handler {
	return &Handler{
		AuthHandler:  NewAuthHandler(authService),
		TwoFAHandler: NewTwoFAHandler(authService),
		UserHandler:  NewUserHandler(authService),
	}
}