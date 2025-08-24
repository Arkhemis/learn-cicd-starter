package auth

import (
    "net/http"
    "testing"
)

func TestGetAPIKey(t *testing.T) {
    // Test case 1: Valid API key
    t.Run("valid API key", func(t *testing.T) {
        headers := http.Header{}
        headers.Set("Authorization", "ApiKey abc123")
        
        result, err := GetAPIKey(headers)
        
        if err != nil {
            t.Errorf("Expected no error, got %v", err)
        }
        if result != "abc123" {
            t.Errorf("Expected 'abc123', got '%s'", result)
        }
    })

    // Test case 2: Missing authorization header
    t.Run("missing authorization header", func(t *testing.T) {
        headers := http.Header{}
        
        result, err := GetAPIKey(headers)
        
        if err != ErrNoAuthHeaderIncluded {
            t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
        }
        if result != "" {
            t.Errorf("Expected empty string, got '%s'", result)
        }
    })

    // Test case 3: Malformed authorization header (wrong prefix)
    t.Run("malformed header - wrong prefix", func(t *testing.T) {
        headers := http.Header{}
        headers.Set("Authorization", "Bearer abc123")
        
        result, err := GetAPIKey(headers)
        
        if err == nil {
            t.Error("Expected error for malformed header, got nil")
        }
        if err.Error() != "malformed authorization header" {
            t.Errorf("Expected 'malformed authorization header', got '%v'", err)
        }
        if result != "" {
            t.Errorf("Expected empty string, got '%s'", result)
        }
    })

    // Test case 4: Malformed authorization header (missing key part)
    t.Run("malformed header - missing key", func(t *testing.T) {
        headers := http.Header{}
        headers.Set("Authorization", "ApiKey")
        
        result, err := GetAPIKey(headers)
        
        if err == nil {
            t.Error("Expected error for malformed header, got nil")
        }
        if err.Error() != "malformed authorization header" {
            t.Errorf("Expected 'malformed authorization header', got '%v'", err)
        }
        if result != "" {
            t.Errorf("Expected empty string, got '%s'", result)
        }
    })
}