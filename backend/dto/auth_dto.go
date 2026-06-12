package dto

// LoginRequest is the payload for the login endpoint.
type LoginRequest struct {
	Username string `json:"username" validate:"required" example:"admin"`
	Password string `json:"password" validate:"required" example:"change-me"`
}

// LoginResponse is returned on a successful login. The token must be sent back
// as `Authorization: Bearer <token>` on every protected request.
type LoginResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type" example:"Bearer"`
	ExpiresAt string `json:"expires_at" example:"2026-06-13T10:00:00Z"`
	Username  string `json:"username" example:"admin"`
}
