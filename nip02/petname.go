package nip02

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ParsePetnamePath parses references like "~erin/david/frank" into ["erin" "david" "frank"].
// An empty first name ("~/name") refers to the current user. Other empty names
// (e.g. "~erin//frank", "~/") are rejected.
func ParsePetnamePath(value string) ([]string, error) {
	if !strings.HasPrefix(value, "~") {
		return nil, fmt.Errorf("invalid petname reference \"%s\": must start with \"~\"", value)
	}

	inner := strings.TrimPrefix(value, "~")
	if inner == "" {
		return nil, fmt.Errorf("empty petname reference")
	}

	parts := strings.Split(inner, "/")
	for i, part := range parts {
		if part == "" && i != 0 {
			return nil, fmt.Errorf("invalid petname reference \"%s\": empty name", value)
		}
	}

	return parts, nil
}

// IsValidPetname reports whether name is usable as a single petname segment:
// at most 64 characters, all printable ASCII (33-126).
func IsValidPetname(name string) bool {
	if utf8.RuneCountInString(name) > 64 {
		return false
	}
	for _, r := range name {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
