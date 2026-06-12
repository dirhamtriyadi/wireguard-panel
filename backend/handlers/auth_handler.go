package handlers

import (
	"net/http"
	"time"

	"github.com/example/wg-panel/auth"
	"github.com/example/wg-panel/dto"
	"github.com/example/wg-panel/middleware"
	"github.com/gin-gonic/gin"
)

// AuthHandler groups authentication endpoints.
type AuthHandler struct {
	svc *auth.Service
}

// NewAuthHandler builds an AuthHandler.
func NewAuthHandler(svc *auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Login godoc
// @Summary      Log in
// @Description  Exchange the admin credentials (from the environment) for a bearer token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      dto.LoginRequest  true  "Login payload"
// @Success      200   {object}  dto.APIResponse
// @Failure      401   {object}  dto.ErrorResponse
// @Failure      422   {object}  dto.ErrorResponse
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.Error(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if errs := middleware.Validate(req); errs != nil {
		dto.ValidationError(c, errs)
		return
	}

	if !h.svc.Enabled() {
		dto.Error(c, http.StatusServiceUnavailable, "authentication is not configured; set AUTH_USERNAME and AUTH_PASSWORD")
		return
	}
	if !h.svc.Authenticate(req.Username, req.Password) {
		dto.Error(c, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, expiresAt, err := h.svc.Issue(time.Now())
	if err != nil {
		dto.Error(c, http.StatusInternalServerError, "failed to issue token")
		return
	}

	dto.OK(c, "login successful", dto.LoginResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Username:  req.Username,
	})
}

// Me godoc
// @Summary      Current user
// @Description  Return the authenticated user; useful to validate a stored token.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  dto.APIResponse
// @Failure      401  {object}  dto.ErrorResponse
// @Router       /auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	user, _ := c.Get(middleware.ContextAuthUser)
	dto.OK(c, "data fetched successfully", gin.H{"username": user})
}
