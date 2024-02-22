package authz

import (
    "net/http"
    "strings"

    "github.com/casbin/casbin/v2"
    "github.com/gin-gonic/gin"
		"fmt"
)

// CustomAuthorizer is a custom authorizer that checks roles in the Gin context for permissions.
type CustomAuthorizer struct {
    enforcer *casbin.Enforcer
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

	// Get the HTTP method from the Gin context
	method := c.Request.Method

	// Extract and validate the orgid from the path
	path := c.Request.URL.Path
    orgID := c.Get("orgId")
	orgID, newPath, valid := validateAndStripOrgID(path,orgID)
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
func validateAndStripOrgID(path string, userOrgId) (orgID, newPath string, valid bool) {
	// Example path: /v1/organisations/12345/users
	segments := strings.Split(path, "/")
	if len(segments) >= 4 && segments[1] == "v1" && segments[2] == "organisations" {
		orgID := segments[3]
        if orgID != userOrgId {
            return "", "", false
        }
		valid = true // orgID is valid
		newPath := "/" + strings.Join(segments[4:], "/") // Reconstruct path without the orgID part
		return orgID, newPath, valid
	}
	return "", "", false
}

// RequirePermission returns the 403 Forbidden status to the client
func (a *CustomAuthorizer) RequirePermission(c *gin.Context) {
    c.AbortWithStatus(http.StatusForbidden)
}
