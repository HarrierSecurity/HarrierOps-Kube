package output

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"harrierops-kube/internal/testutil"
)

func assertUniformTableWidth(t *testing.T, rendered string) {
	t.Helper()

	tableWidth := 0
	sawTableLine := false
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "|") {
			continue
		}
		sawTableLine = true
		lineWidth := lipgloss.Width(line)
		if tableWidth == 0 {
			tableWidth = lineWidth
			continue
		}
		if lineWidth != tableWidth {
			t.Fatalf("table display width = %d, want %d: %q", lineWidth, tableWidth, line)
		}
	}
	if !sawTableLine {
		t.Fatalf("rendered output did not include table lines: %q", rendered)
	}
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
	assertUniformTableWidth(t, rendered)

	normalized := testutil.NormalizeTableText(rendered)
	for _, want := range []string{
		"name (current",
		"session)",
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
	for _, want := range []string{
		"attack angle",
		"authorization API",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing raw text %q in %q", want, rendered)
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

	assertUniformTableWidth(t, rendered)
	for _, want := range []string{
		"no exposed path seen",
		"attack angle",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing %q in %q", want, rendered)
		}
	}
	normalized := testutil.NormalizeTableText(rendered)
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

	assertUniformTableWidth(t, rendered)
}

func TestRenderServiceAccountsTableKeepsAlignedWidthWithLongTokenPosture(t *testing.T) {
	payload := map[string]any{
		"service_accounts": []any{
			map[string]any{
				"priority":          "high",
				"namespace":         "default",
				"name":              "fox-admin",
				"workload_count":    2,
				"related_workloads": []any{"default/fox-admin", "default/api"},
				"power_summary":     "has cluster-wide admin-like access",
				"token_posture":     "token auto-mount is visible on 2 attached workloads; legacy token secret is visible; runtime token review is still not proven from current scope",
				"why_care":          "This identity path matters because the attached workloads are already central and the visible token posture still changes the next move.",
			},
		},
	}

	rendered, err := Render("table", "service-accounts", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	assertUniformTableWidth(t, rendered)
	for _, want := range []string{
		"harrierops-kube service-accounts",
		"attack angle",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing raw text %q in %q", want, rendered)
		}
	}

	normalized := testutil.NormalizeTableText(rendered)
	for _, want := range []string{
		"fox-admin",
		"cluster-wide",
		"admin-like",
		"legacy token secret is visible",
		"current scope",
		"This identity path matters because the attached workloads are already central",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("normalized rendered output missing %q in %q", want, normalized)
		}
	}
}

func TestRenderWhoAmITableKeepsAlignedWidthWithLongEvidence(t *testing.T) {
	payload := map[string]any{
		"kube_context": map[string]any{
			"cluster_name":    "lab-cluster",
			"server":          "https://10.0.0.1:6443",
			"current_context": "lab-cluster",
			"namespace":       "default",
			"user":            "fox-operator",
			"server_version":  "v1.30.1",
		},
		"current_identity": map[string]any{
			"label":      "fox-operator",
			"kind":       "User",
			"confidence": "direct",
		},
		"session": map[string]any{
			"foothold_family":    "cloud-bridged",
			"auth_material_type": "exec-plugin",
			"execution_origin":   "outside-cluster",
			"visibility_scope":   "cluster-scoped",
		},
		"environment_hint": map[string]any{
			"summary":    "The visible API endpoint looks private or lab-shaped rather than strongly managed-service-branded.",
			"type":       "self-managed-like",
			"confidence": "heuristic",
			"evidence": []any{
				"The visible API endpoint is an internal-style address without strong managed-cluster branding.",
			},
		},
		"identity_evidence": []any{
			"The active kubeconfig context names user 'fox-operator'.",
			"The current auth path shows an exec-plugin style kubeconfig flow with enough context to trust the session shape.",
		},
	}

	rendered, err := Render("table", "whoami", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	assertUniformTableWidth(t, rendered)
	for _, want := range []string{
		"harrierops-kube whoami",
		"Identity Evidence",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing raw text %q in %q", want, rendered)
		}
	}

	normalized := testutil.NormalizeTableText(rendered)
	for _, want := range []string{
		"Cluster",
		"lab-cluster",
		"Environment Hint",
		"managed-",
		"service-branded",
		"Identity Evidence",
		"exec-plugin style kubeconfig flow",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("normalized rendered output missing %q in %q", want, normalized)
		}
	}
}

func TestRenderChainsFamilyTableShowsSelectedFamilyHeaderAndTakeaway(t *testing.T) {
	payload := map[string]any{
		"family":           "workload-identity-pivot",
		"summary":          "2 workload-linked identity paths are ready for first review.",
		"backing_commands": []any{"workloads", "service-accounts", "permissions", "secrets"},
		"paths": []any{
			map[string]any{
				"priority":                  "high",
				"source_asset":              "default/web",
				"subversion_point":          "switch workload default/web to service account default/fox-admin",
				"path_type":                 "direct control visible",
				"likely_kubernetes_control": "service account default/fox-admin has cluster-wide admin-like access",
				"visibility_tier":           "high",
				"next_review":               "workloads",
				"why_stop_here":             "current foothold can change an already running workload with stronger identity",
				"confidence_boundary":       "Current scope confirms the workload service account field is changeable.",
				"summary":                   "visible target and action edge align cleanly",
			},
			map[string]any{
				"priority":                  "medium",
				"source_asset":              "default/fox-admin",
				"subversion_point":          "review visible workload-linked token path on default/fox-admin",
				"path_type":                 "direct control not confirmed",
				"likely_kubernetes_control": "attached service account has cluster-wide admin-like access",
				"visibility_tier":           "medium",
				"next_review":               "review visible token path",
				"why_stop_here":             "runtime token inspection is not yet proven",
				"confidence_boundary":       "Current scope confirms a workload-linked token path is visible, but runtime inspection is not yet proven.",
				"summary":                   "visible target and identity path are present",
			},
		},
	}

	rendered, err := Render("table", "chains", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	assertUniformTableWidth(t, rendered)
	normalized := testutil.NormalizeTableText(rendered)
	for _, want := range []string{
		"harrierops-kube chains workload-identity-pivot",
		"Summary: 2 workload-linked identity paths are ready for first review.",
		"Backing commands: workloads, service-accounts, permissions, secrets",
		"subversion point",
		"direct control",
		"visible default/fox-admin",
		"review visible",
		"workload-linked",
		"token path on",
		"default/fox-admin",
		"Takeaway: 2 visible workload-identity pivot row(s); 1 high, 1 medium, 0 low.",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("rendered output missing %q in %q", want, normalized)
		}
	}
	for _, want := range []string{
		"harrierops-kube chains workload-identity-pivot",
		"Takeaway: 2 visible workload-identity pivot row(s); 1 high, 1 medium, 0 low.",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing raw text %q in %q", want, rendered)
		}
	}
}

func TestRenderChainsFamilyTableKeepsFamilyContextInEmptyState(t *testing.T) {
	payload := map[string]any{
		"family":           "workload-identity-pivot",
		"summary":          "No bounded workload-identity pivot rows were confirmed from current scope.",
		"backing_commands": []any{"workloads", "service-accounts", "permissions", "secrets"},
		"paths":            []any{},
	}

	rendered, err := Render("table", "chains", payload)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	normalized := testutil.NormalizeTableText(rendered)
	for _, want := range []string{
		"harrierops-kube chains workload-identity-pivot",
		"Summary: No bounded workload-identity pivot rows were confirmed from current scope.",
		"Backing commands: workloads, service-accounts, permissions, secrets",
		"No bounded workload-identity pivot rows were confirmed from current scope.",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("rendered output missing %q in %q", want, normalized)
		}
	}
	for _, want := range []string{
		"harrierops-kube chains workload-identity-pivot",
		"No bounded workload-identity pivot rows were confirmed from current scope.",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing raw text %q in %q", want, rendered)
		}
	}
}
