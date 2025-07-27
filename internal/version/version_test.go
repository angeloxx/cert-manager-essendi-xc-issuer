package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name        string
		expectEmpty bool
	}{
		{
			name:        "version-not-empty",
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectEmpty {
				assert.Empty(t, Version)
			} else {
				assert.NotEmpty(t, Version)
				// Version should be a valid semver-like string
				assert.Contains(t, Version, ".")
			}
		})
	}
}

func TestVersionConstant(t *testing.T) {
	// Test that version is set to a reasonable default
	assert.Equal(t, "0.1.0", Version)
}

func TestVersionIsString(t *testing.T) {
	// Ensure Version is a string type
	var v interface{} = Version
	_, ok := v.(string)
	assert.True(t, ok, "Version should be a string")
}