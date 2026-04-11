package testutil

import "strings"

func NormalizeWhitespace(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func NormalizeTableText(text string) string {
	lines := strings.Split(text, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Trim(trimmed, "+-|") == "" {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "|")
		trimmed = strings.TrimSuffix(trimmed, "|")
		trimmed = strings.ReplaceAll(trimmed, "|", " ")
		parts = append(parts, trimmed)
	}
	return NormalizeWhitespace(strings.Join(parts, " "))
}
