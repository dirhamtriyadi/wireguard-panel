package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/example/wg-panel/auth"
	"github.com/example/wg-panel/dto"
	"github.com/gin-gonic/gin"
)

// ContextAuthUser is the gin context key holding the authenticated username.
const ContextAuthUser = "auth_user"

const bearerPrefix = "Bearer "

// Auth guards protected routes: it requires a valid `Authorization: Bearer`
// token issued by the auth service. When credentials are not configured the
// API is locked rather than left open.
func Auth(svc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !svc.Enabled() {
			dto.Error(c, http.StatusServiceUnavailable, "authentication is not configured; set AUTH_USERNAME and AUTH_PASSWORD")
			c.Abort()
			return
		}

		header := strings.TrimSpace(c.GetHeader("Authorization"))
		if !strings.HasPrefix(header, bearerPrefix) {
			dto.Error(c, http.StatusUnauthorized, "authentication required")
			c.Abort()
			return
		}

		token := strings.TrimSpace(header[len(bearerPrefix):])
		user, err := svc.Validate(token, time.Now())
		if err != nil {
			dto.Error(c, http.StatusUnauthorized, "invalid or expired token")
			c.Abort()
			return
		}

		c.Set(ContextAuthUser, user)
		c.Next()
	}
}
