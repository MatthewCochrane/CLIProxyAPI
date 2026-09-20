package codex

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"
)

// AccountIDHash returns a bounded collision-resistant identifier for credential filenames.
func AccountIDHash(accountID string) string {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(accountID))
	return fmt.Sprintf("%x", digest[:16])
}

// CredentialFileName returns the filename used to persist Codex OAuth credentials.
// The account hash is included when available to keep accounts with the same email
// and plan distinct. The legacy email-based format remains the fallback.
func CredentialFileName(email, planType, hashAccountID string, includeProviderPrefix bool) string {
	email = safeCredentialFilenameComponent(email, "account")
	plan := normalizePlanTypeForFilename(planType)
	if strings.TrimSpace(hashAccountID) != "" {
		hashAccountID = safeCredentialFilenameComponent(hashAccountID, "account")
	}

	prefix := ""
	if includeProviderPrefix {
		prefix = "codex"
	}

	if hashAccountID != "" {
		if plan == "" {
			return fmt.Sprintf("%s-%s-%s.json", prefix, hashAccountID, email)
		}
		return fmt.Sprintf("%s-%s-%s-%s.json", prefix, hashAccountID, email, plan)
	}
	if plan == "" {
		return fmt.Sprintf("%s-%s.json", prefix, email)
	}
	return fmt.Sprintf("%s-%s-%s.json", prefix, email, plan)
}

func safeCredentialFilenameComponent(value, fallback string) string {
	value = strings.TrimSpace(value)
	var component strings.Builder
	replaced := false
	lastWasDash := false
	for _, r := range value {
		safe := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@._+-", r)
		if safe && component.Len() < 120 {
			component.WriteRune(r)
			lastWasDash = false
			continue
		}
		replaced = true
		if !lastWasDash && component.Len() < 120 {
			component.WriteByte('-')
			lastWasDash = true
		}
	}

	cleaned := strings.Trim(component.String(), ".-_+@")
	if cleaned == "" {
		cleaned = fallback
		replaced = value != fallback
	}
	if replaced || cleaned != value {
		digest := sha256.Sum256([]byte(value))
		cleaned = fmt.Sprintf("%s-%x", cleaned, digest[:16])
	}
	return cleaned
}

func normalizePlanTypeForFilename(planType string) string {
	planType = strings.TrimSpace(planType)
	if planType == "" {
		return ""
	}

	parts := strings.FieldsFunc(planType, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(parts) == 0 {
		return ""
	}

	for i, part := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(part))
	}
	return strings.Join(parts, "-")
}
