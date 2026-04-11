package output

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
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
				"evidence_source":    "authorization API",
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
		"(current session)",
		"visibility blocked",
		"authorization API",
		"review the exact",
		"binding path and",
		"current-session capability path",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("rendered output missing %q in %q", want, normalized)
		}
	}
}

func TestRenderDetailedRecordTableClosesRowBoxBeforeDetailSection(t *testing.T) {
	rendered, err := renderDetailedRecordTable(
		[]string{"priority", "workload"},
		[]int{8, 17},
		[]string{"high", "default/fox-admin"},
		"attack angle",
		"this workload may be able to control other containers on the same machine.",
	)
	if err != nil {
		t.Fatalf("renderDetailedRecordTable() error = %v", err)
	}

	lines := strings.Split(rendered, "\n")
	rowLineIndex := -1
	for index, line := range lines {
		if strings.Contains(line, "default/fox-admin") {
			rowLineIndex = index
			break
		}
	}
	if rowLineIndex == -1 {
		t.Fatalf("rendered output missing record row: %q", rendered)
	}
	if rowLineIndex+2 >= len(lines) {
		t.Fatalf("rendered output too short to include closed detail section: %q", rendered)
	}
	if !strings.HasPrefix(lines[rowLineIndex+1], "+-") {
		t.Fatalf("record row is not closed by a border before detail section: %q", rendered)
	}
	if !strings.Contains(lines[rowLineIndex+2], "attack angle") {
		t.Fatalf("detail label does not begin immediately after the closing border: %q", rendered)
	}
}

func TestRenderWorkloadsTableKeepsAlignedAttachedDetailBox(t *testing.T) {
	payload := map[string]any{
		"workload_assets": []any{
			map[string]any{
				"priority":              "high",
				"namespace":             "default",
				"name":                  "fox-admin",
				"identity_summary":      "runs as default/fox-admin (has cluster-wide admin-like access)",
				"service_account_power": "has cluster-wide admin-like access",
				"risk_signals": []any{
					"privileged container",
					"workload can reach the container runtime socket on the host",
					"workload mounts host directories",
				},
			},
		},
	}

	rendered, err := Render("table", "workloads", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	lines := strings.Split(rendered, "\n")
	tableWidth := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "|") {
			continue
		}
		if tableWidth == 0 {
			tableWidth = len(line)
			continue
		}
		if len(line) != tableWidth {
			t.Fatalf("workloads table line width = %d, want %d: %q", len(line), tableWidth, line)
		}
	}
	if tableWidth == 0 {
		t.Fatalf("rendered workloads output did not include table lines: %q", rendered)
	}
	for _, want := range []string{
		"no exposed path seen",
		"attack angle",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing %q in %q", want, rendered)
		}
	}
	normalized := normalizedWriterText(rendered)
	for _, want := range []string{
		"this workload may be able to control other containers on the same machine.",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("normalized rendered output missing %q in %q", want, normalized)
		}
	}
}

func TestRenderWorkloadsTableKeepsAlignedWidthWithWrappedMultibyteContent(t *testing.T) {
	payload := map[string]any{
		"workload_assets": []any{
			map[string]any{
				"priority":              "high",
				"namespace":             "default",
				"name":                  "fox-admin",
				"identity_summary":      "runs as default/fox-admin (管理者に近い権限が見えている current session path)",
				"service_account_power": "has cluster-wide admin-like access",
				"risk_signals": []any{
					"workload can reach the container runtime socket on the host",
					"workload mounts host directories",
				},
			},
		},
	}

	rendered, err := Render("table", "workloads", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	tableWidth := 0
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "|") {
			continue
		}
		lineWidth := lipgloss.Width(line)
		if tableWidth == 0 {
			tableWidth = lineWidth
			continue
		}
		if lineWidth != tableWidth {
			t.Fatalf("workloads table display width = %d, want %d: %q", lineWidth, tableWidth, line)
		}
	}
	if tableWidth == 0 {
		t.Fatalf("rendered workloads output did not include table lines: %q", rendered)
	}
}
