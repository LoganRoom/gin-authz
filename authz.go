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

    // Get the HTTP method and URL path from the Gin context
    method := c.Request.Method
		fmt.Println("method: ", method)
    path := c.FullPath()
fmt.Println("path: ", path)
    // Check each role for permission
    for _, role := range roleSlice {
				fmt.Println("roles: ", role)
        allowed, err := a.enforcer.Enforce(role, path, method)
        if err != nil {
					fmt.Println("err: ", err)
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

// RequirePermission returns the 403 Forbidden status to the client
func (a *CustomAuthorizer) RequirePermission(c *gin.Context) {
    c.AbortWithStatus(http.StatusForbidden)
}
