package output

import (
	"strings"
	"testing"
)

func normalizedWriterText(text string) string {
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
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

func TestRenderTableWrapsLongDetailedRows(t *testing.T) {
	payload := map[string]any{
		"permissions": []any{
			map[string]any{
				"priority":           "high",
				"subject":            "system:serviceaccount:payments:very-long-application-service-account-name (current session)",
				"subject_confidence": "visibility blocked",
				"action_summary":     "can change workloads and can impersonate serviceaccounts across several visible namespaces from current scope",
				"scope":              "cluster-wide plus namespace-scoped paths that are still partly visibility limited",
				"next_review":        "review the exact binding path and confirm whether the wider subject reuse is real before acting",
				"why_care":           "This row should stay readable even when the subject, action summary, and next review are all longer than a comfortable terminal line.",
			},
		},
	}

	rendered, err := Render("table", "permissions", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	for _, line := range strings.Split(rendered, "\n") {
		if len(line) > 150 {
			t.Fatalf("rendered line too wide (%d chars): %q", len(line), line)
		}
	}

	normalized := normalizedWriterText(rendered)
	for _, want := range []string{
		"system:serviceaccount:",
		"payments:very-long-app",
		"lication-service-accou",
		"nt-name",
		"(current session)",
		"visibility blocked",
		"review the exact",
		"binding path and",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("rendered output missing %q in %q", want, normalized)
		}
	}
}
