package app

import (
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
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
					EvidenceStatus:   "direct",
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
	if !strings.Contains(row["why_care"].(string), "identity match is inferred") {
		t.Fatalf("why_care = %q, want inferred-identity wording", row["why_care"])
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
