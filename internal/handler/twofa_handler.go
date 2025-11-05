package handler

import (
	"net/http"

	"authentio/internal/service"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// TwoFAHandler Structure and Constructor
// =============================================================================

// TwoFAHandler handles 2FA-related HTTP requests
type TwoFAHandler struct {
	authService service.AuthService
}

// NewTwoFAHandler creates a new TwoFAHandler instance
func NewTwoFAHandler(authService service.AuthService) *TwoFAHandler {
	return &TwoFAHandler{
		authService: authService,
	}
}

// =============================================================================
// 2FA Management Endpoints (Protected - Require Authentication)
// =============================================================================

// EnableEmail2FA godoc
// @Summary Enable email-based 2FA
// @Description Enable two-factor authentication using email for the authenticated user
// @Tags 2fa
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "2FA enabled successfully"
// @Failure 400 {object} map[string]string "Failed to enable 2FA"
// @Failure 401 {object} map[string]string "Unauthorized - Invalid or missing JWT token"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /2fa/enableOtp [post]
func (h *TwoFAHandler) EnableEmail2FA(c *gin.Context) {
	// Get userID from JWT token (set by auth middleware)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.authService.EnableEmail2FA(c.Request.Context(), userID.(int64)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA enabled successfully"})
}

// Disable2FA godoc
// @Summary Disable 2FA
// @Description Disable two-factor authentication for the authenticated user
// @Tags 2fa
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "2FA disabled successfully"
// @Failure 400 {object} map[string]string "Failed to disable 2FA"
// @Failure 401 {object} map[string]string "Unauthorized - Invalid or missing JWT token"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /2fa/disableOtp [post]
func (h *TwoFAHandler) Disable2FA(c *gin.Context) {
	// Get userID from JWT token (set by auth middleware)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.authService.Disable2FA(c.Request.Context(), userID.(int64)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA disabled successfully"})
}

// =============================================================================
// OTP Management Endpoints (Public - Used during login flow)
// =============================================================================

// SendOTP godoc
// @Summary Send 2FA OTP code
// @Description Send a one-time password to the user's email for two-factor authentication
// @Tags 2fa
// @Accept json
// @Produce json
// @Param request body SendOTPRequest true "Email address to send OTP"
// @Success 200 {object} map[string]string "OTP sent successfully"
// @Failure 400 {object} map[string]string "Invalid email format or user not found"
// @Failure 500 {object} map[string]string "Failed to send OTP email"
// @Router /2fa/sendOtp [post]
func (h *TwoFAHandler) SendOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.Send2FAOTP(c.Request.Context(), req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

// VerifyOTP godoc
// @Summary Verify 2FA OTP code
// @Description Verify the one-time password for two-factor authentication
// @Tags 2fa
// @Accept json
// @Produce json
// @Param request body VerifyOTPRequest true "OTP verification data"
// @Success 200 {object} map[string]string "OTP verified successfully"
// @Failure 400 {object} map[string]string "Invalid OTP code, expired code, or invalid email"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /2fa/verifyOtp [post]
func (h *TwoFAHandler) VerifyOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		Code  string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.Verify2FA(c.Request.Context(), req.Email, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
}