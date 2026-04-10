package app

import (
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/output"
	"harrierops-kube/internal/provider"
)

func TestPermissionsPayloadSummarizesCurrentFootholdCapabilities(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "prod", Namespace: "payments"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "analyst@example.com",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:     "analyst-impersonate",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"impersonate serviceaccounts"},
					EvidenceStatus:  "direct",
				},
				{
					BindingName:     "analyst-secrets",
					Scope:           "namespace/payments",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"read secrets"},
					EvidenceStatus:  "direct",
				},
				{
					BindingName:     "someone-else",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "other@example.com",
					DangerousRights: []string{"admin-like wildcard access"},
					EvidenceStatus:  "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rows, ok := payload["permissions"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("permissions = %#v, want two rows", payload["permissions"])
	}

	first := requireMap(t, rows[0])
	if first["subject"] != "analyst@example.com (current session)" {
		t.Fatalf("first subject = %v, want current-session label", first["subject"])
	}
	if first["action_summary"] != "can impersonate serviceaccounts" {
		t.Fatalf("first action_summary = %v, want impersonation first", first["action_summary"])
	}
	if first["scope"] != "cluster-wide" {
		t.Fatalf("first scope = %v, want cluster-wide", first["scope"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["next_review"] != "rbac" {
		t.Fatalf("first next_review = %v, want rbac", first["next_review"])
	}

	second := requireMap(t, rows[1])
	if second["action_summary"] != "can read secrets" {
		t.Fatalf("second action_summary = %v, want can read secrets", second["action_summary"])
	}
	if second["priority"] != "medium" {
		t.Fatalf("second priority = %v, want medium", second["priority"])
	}
	if !strings.Contains(second["why_care"].(string), "widen access beyond this foothold") {
		t.Fatalf("second why_care = %q, want secret-read explanation", second["why_care"])
	}
}

func TestPermissionsPayloadUsesInferredCurrentIdentityLabel(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "prod", Namespace: "payments"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "system:serviceaccount:payments:api",
				Kind:       "ServiceAccount",
				Namespace:  stringPtr("payments"),
				Confidence: "inferred",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:      "api-edit",
					Scope:            "namespace/payments",
					SubjectKind:      "ServiceAccount",
					SubjectName:      "api",
					SubjectNamespace: stringPtr("payments"),
					DangerousRights:  []string{"change workloads"},
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "patch",
							TargetGroup:     "workload-controllers",
							TargetResources: []string{"deployments", "statefulsets"},
							Summary:         "can patch workload controllers",
						},
					},
					EvidenceStatus: "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rows, ok := payload["permissions"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("permissions = %#v, want one row", payload["permissions"])
	}

	row := requireMap(t, rows[0])
	if row["subject"] != "system:serviceaccount:payments:api (current session)" {
		t.Fatalf("subject = %v, want inferred current-session label", row["subject"])
	}
	if row["subject_confidence"] != "inferred" {
		t.Fatalf("subject_confidence = %v, want inferred", row["subject_confidence"])
	}
	if row["action_summary"] != "can patch workload controllers" {
		t.Fatalf("action_summary = %v, want exact workload action", row["action_summary"])
	}
	targetResources, ok := row["target_resources"].([]any)
	if !ok || len(targetResources) != 2 {
		t.Fatalf("target_resources = %#v, want deployment and statefulset coverage", row["target_resources"])
	}
	if !strings.Contains(row["why_care"].(string), "identity match is inferred") {
		t.Fatalf("why_care = %q, want inferred-identity wording", row["why_care"])
	}
}

func TestPermissionsPayloadPrefersExactWorkloadActionsOverGenericBucket(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "payments"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "operator@example.com",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:     "operator-edit",
					Scope:           "namespace/payments",
					SubjectKind:     "User",
					SubjectName:     "operator@example.com",
					DangerousRights: []string{"change workloads", "exec into pods"},
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "create",
							TargetGroup:     "pods",
							TargetResources: []string{"pods"},
							Summary:         "can create pods",
						},
						{
							Verb:            "patch",
							TargetGroup:     "workload-controllers",
							TargetResources: []string{"deployments", "statefulsets"},
							Summary:         "can patch workload controllers",
						},
						{
							Verb:            "exec",
							TargetGroup:     "pods",
							TargetResources: []string{"pods/exec"},
							Summary:         "can exec into pods",
						},
					},
					EvidenceStatus: "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rows, ok := payload["permissions"].([]any)
	if !ok || len(rows) != 3 {
		t.Fatalf("permissions = %#v, want three exact rows", payload["permissions"])
	}

	seen := map[string]map[string]any{}
	for _, row := range rows {
		mapping := requireMap(t, row)
		seen[mapping["action_summary"].(string)] = mapping
	}

	if _, ok := seen["can change workloads"]; ok {
		t.Fatalf("permissions = %#v, want exact workload rows instead of generic change workloads", rows)
	}
	if _, ok := seen["can create pods"]; !ok {
		t.Fatalf("permissions = %#v, want can create pods", rows)
	}
	if _, ok := seen["can patch workload controllers"]; !ok {
		t.Fatalf("permissions = %#v, want can patch workload controllers", rows)
	}
	execRow, ok := seen["can exec into pods"]
	if !ok {
		t.Fatalf("permissions = %#v, want can exec into pods", rows)
	}
	if execRow["target_group"] != "pods" {
		t.Fatalf("exec target_group = %v, want pods", execRow["target_group"])
	}
}

func TestPermissionsPayloadRecognizesNodeAndPolicyCapabilityFamilies(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "kube-system"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "ops@example.com",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:     "ops-nodes",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "ops@example.com",
					DangerousRights: []string{"touch nodes"},
					EvidenceStatus:  "direct",
				},
				{
					BindingName:     "ops-policy",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "ops@example.com",
					DangerousRights: []string{"change admission or policy"},
					EvidenceStatus:  "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rows, ok := payload["permissions"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("permissions = %#v, want two rows", payload["permissions"])
	}

	first := requireMap(t, rows[0])
	if first["action_summary"] != "can touch nodes" {
		t.Fatalf("first action_summary = %v, want can touch nodes", first["action_summary"])
	}
	if first["next_review"] != "privesc" {
		t.Fatalf("first next_review = %v, want privesc", first["next_review"])
	}
	if !strings.Contains(first["why_care"].(string), "host or control-plane influence") {
		t.Fatalf("first why_care = %q, want node-adjacent wording", first["why_care"])
	}

	second := requireMap(t, rows[1])
	if second["action_summary"] != "can change admission or policy" {
		t.Fatalf("second action_summary = %v, want can change admission or policy", second["action_summary"])
	}
	if second["next_review"] != "privesc" {
		t.Fatalf("second next_review = %v, want privesc", second["next_review"])
	}
}

func TestPermissionsPayloadReportsBlockedCurrentIdentity(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "shared-lab", Namespace: "default"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "unknown current identity",
				Kind:       "Unknown",
				Confidence: "blocked",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:     "mystery-binding",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "fox-operator",
					DangerousRights: []string{"read secrets"},
					EvidenceStatus:  "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rows, ok := payload["permissions"].([]any)
	if !ok || len(rows) != 0 {
		t.Fatalf("permissions = %#v, want empty rows when identity is blocked", payload["permissions"])
	}

	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) == 0 {
		t.Fatalf("issues = %#v, want visibility issue", payload["issues"])
	}

	found := false
	for _, issue := range issues {
		mapping := requireMap(t, issue)
		if mapping["scope"] == "permissions.identity" {
			found = strings.Contains(mapping["message"].(string), "not visible from current credentials")
			break
		}
	}
	if !found {
		t.Fatalf("issues = %#v, want permissions.identity visibility wording", issues)
	}
}

func TestPermissionsPayloadBubblesRBACError(t *testing.T) {
	_, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "prod", Namespace: "default"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "fox-operator",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		rbacErr: errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("err = %v, want RBAC failure surfaced", err)
	}
}

func TestPermissionsTableOutputStaysOperatorReadable(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "prod", Namespace: "payments"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "analyst@example.com",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					BindingName:     "analyst-impersonate",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"impersonate serviceaccounts"},
					EvidenceStatus:  "direct",
				},
			},
		},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rendered, err := output.Render("table", "permissions", payload)
	if err != nil {
		t.Fatalf("output.Render() error = %v", err)
	}

	renderedText := normalizedTableText(rendered)
	for _, want := range []string{
		"harrierops-kube permissions",
		"priority",
		"subject",
		"confidence",
		"action",
		"scope",
		"next_review",
		"analyst@example.com (current",
		"session)",
		"can impersonate serviceaccounts",
	} {
		if !strings.Contains(renderedText, want) {
			t.Fatalf("table output missing %q in %q", want, renderedText)
		}
	}
}

func TestPermissionsTableOutputExplainsBlockedIdentity(t *testing.T) {
	payload, err := buildPermissionsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "shared-lab", Namespace: "default"},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "unknown current identity",
				Kind:       "Unknown",
				Confidence: "blocked",
			},
		},
		rbacData: model.RBACData{},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPermissionsPayload() error = %v", err)
	}

	rendered, err := output.Render("table", "permissions", payload)
	if err != nil {
		t.Fatalf("output.Render() error = %v", err)
	}

	for _, want := range []string{
		"harrierops-kube permissions",
		"info",
		"No visible current-session capability paths were confirmed from current scope.",
		"Issues:",
		"visibility (permissions.identity): Current session identity is not visible from current credentials, so current-foothold capability triage is incomplete.",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}
