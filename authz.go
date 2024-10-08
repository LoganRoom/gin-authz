package authz

import (
	"net/http"
	"strings"

	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

// CustomAuthorizer is a custom authorizer that checks roles in the Gin context for permissions.
type CustomAuthorizer struct {
	enforcer *casbin.Enforcer
}

// NewCustomAuthorizer returns a custom authorizer that uses a Casbin enforcer as input.
func NewCustomAuthorizer(e *casbin.Enforcer) gin.HandlerFunc {
	a := &CustomAuthorizer{enforcer: e}

	return func(c *gin.Context) {
		if !a.CheckPermission(c) {
			a.RequirePermission(c)
		}
	}
}

// CheckPermission checks if the roles in the Gin context have permission for the requested URL and HTTP verb.
func (a *CustomAuthorizer) CheckPermission(c *gin.Context) bool {
	// Get roles from the Gin context, assuming roles are stored as a comma-delimited string
	roles, exists := c.Get("roles")
	if !exists {
		// No roles found in the context, return false (permission denied)
		return false
	}

	// Convert roles to a slice of strings
	roleSlice := strings.Split(roles.(string), ",")

	for _, role := range roleSlice {
		if role == "admin" {
			// if roleslice contains admin, return true (permission granted)
			fmt.Println("Permission granted to ADMIN user")
			return true
		}
	}
	// Get the HTTP method from the Gin context
	method := c.Request.Method

	// Extract and validate the orgid from the path
	path := c.Request.URL.Path
	orgID, oExists := c.Get("orgId")
	// convert uint orgID to string
	orgID = fmt.Sprint(orgID)

	if orgID == "0" || !oExists {
		// if roleslice contains admin, return true (permission granted)

		// if orgID is not set, return false (permission denied)
		return false
	}

	// Perform type assertion to convert orgID to a string
	orgIDStr, ok := orgID.(string)
	if !ok {
		// orgID is not a string, handle the error, e.g., log, return false, etc.
		fmt.Println("orgID is not a string")
		return false
	}

	orgID, newPath, valid := validateAndStripOrgID(path, orgIDStr)
	if !valid {
		// orgID is not valid, return false (permission denied)
		fmt.Println("Invalid orgID")
		return false
	}

	// Check each role for permission on the new, stripped path
	for _, role := range roleSlice {
		allowed, err := a.enforcer.Enforce(role, newPath, method)
		if err != nil {
			fmt.Println("Error during enforcement: ", err)
			panic(err)
		}
		if allowed {
			// If any role has permission, return true (permission granted)
			return true
		}
	}

	// If no role has permission, return false (permission denied)
	fmt.Println("Permission denied")
	return false
}

// validateAndStripOrgID validates the orgID and returns the stripped path if valid
func validateAndStripOrgID(path string, userOrgId string) (orgID, newPath string, valid bool) {
	// Example path: /v1/organisations/12345/users
	segments := strings.Split(path, "/")
	if len(segments) >= 4 && segments[1] == "v1" && segments[2] == "organisations" {
		orgID := segments[3]
		if orgID != userOrgId {
			return "", "", false
		}
		valid = true                                     // orgID is valid
		newPath := "/" + strings.Join(segments[4:], "/") // Reconstruct path without the orgID part
		return orgID, newPath, valid
	}
	return "", "", false
}

// RequirePermission returns the 403 Forbidden status to the client
func (a *CustomAuthorizer) RequirePermission(c *gin.Context) {
	c.AbortWithStatus(http.StatusForbidden)
}
