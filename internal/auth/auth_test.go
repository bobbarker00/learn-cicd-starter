package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   error
	}{
		{
			name:        "valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectErr:   nil,
		},
		{
			name:        "missing Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed Authorization header",
			headers:     http.Header{"Authorization": []string{"Bearer token"}},
			expectedKey: "",
			expectErr:   errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if (err != nil && tt.expectErr == nil) ||
				(err == nil && tt.expectErr != nil) ||
				(err != nil && tt.expectErr != nil && err.Error() != tt.expectErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}
		})
	}
}
