package app

import (
	"bytes"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func TestPrivescPayloadClassifiesImmediateIdentityAndExecutionPaths(t *testing.T) {
	payload, err := buildPrivescPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "default"},
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
					BindingName:     "impersonate-sa",
					Scope:           "cluster-wide",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"impersonate serviceaccounts"},
					EvidenceStatus:  "direct",
				},
				{
					BindingName:     "mutate-workloads",
					Scope:           "namespace/payments",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"change workloads"},
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "patch",
							TargetGroup:     "workload-controllers",
							TargetResources: []string{"deployments"},
							Summary:         "can patch workload controllers",
						},
					},
					EvidenceStatus: "direct",
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{},
		workloadsData:       model.WorkloadsData{},
		exposuresData:       model.ExposureData{},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPrivescPayload() error = %v", err)
	}

	rows, ok := payload["escalation_paths"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("escalation_paths = %#v, want two immediate rows", payload["escalation_paths"])
	}

	first := requireMap(t, rows[0])
	if first["path_class"] != "identity-control-immediate" {
		t.Fatalf("first path_class = %v, want identity-control-immediate", first["path_class"])
	}
	if first["operator_signal"] != "pivot-now" {
		t.Fatalf("first operator_signal = %v, want pivot-now", first["operator_signal"])
	}
	if first["next_review"] != "rbac" {
		t.Fatalf("first next_review = %v, want rbac", first["next_review"])
	}

	second := requireMap(t, rows[1])
	if second["path_class"] != "execution-control-immediate" {
		t.Fatalf("second path_class = %v, want execution-control-immediate", second["path_class"])
	}
	if second["action"] != "can patch workload controllers" {
		t.Fatalf("second action = %v, want exact workload action", second["action"])
	}
	if second["next_review"] != "workloads" {
		t.Fatalf("second next_review = %v, want workloads", second["next_review"])
	}
}

func TestPrivescPayloadBuildsSecretBackedLeadFromCurrentFoothold(t *testing.T) {
	payload, err := buildPrivescPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "default"},
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
					BindingName:     "read-secrets",
					Scope:           "namespace/default",
					SubjectKind:     "User",
					SubjectName:     "analyst@example.com",
					DangerousRights: []string{"read secrets"},
					EvidenceStatus:  "direct",
				},
				{
					BindingName:      "fox-admin-cluster-admin",
					Scope:            "cluster-wide",
					SubjectKind:      "ServiceAccount",
					SubjectNamespace: stringPtr("default"),
					SubjectName:      "fox-admin",
					DangerousRights:  []string{"admin-like wildcard access"},
					EvidenceStatus:   "direct",
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:default:fox-admin", Namespace: "default", Name: "fox-admin", SecretNames: []string{"fox-admin-token"}},
			},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:default:fox-admin", Namespace: "default", Name: "fox-admin", Kind: "Pod", ServiceAccountName: "fox-admin", Privileged: true},
			},
		},
		exposuresData: model.ExposureData{},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPrivescPayload() error = %v", err)
	}

	rows, ok := payload["escalation_paths"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("escalation_paths = %#v, want non-empty", payload["escalation_paths"])
	}

	found := false
	for _, row := range rows {
		mapping := requireMap(t, row)
		if mapping["path_class"] == "workload-control-backed" {
			found = true
			if mapping["action"] != "read secret path fox-admin-token" {
				t.Fatalf("secret-backed action = %v, want fox-admin-token path", mapping["action"])
			}
			if mapping["next_review"] != "workloads" {
				t.Fatalf("secret-backed next_review = %v, want workloads", mapping["next_review"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected workload-control-backed row in %#v", rows)
	}
}

func TestPrivescPayloadKeepsPostureOnlyRowsLower(t *testing.T) {
	payload, err := buildPrivescPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "default"},
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
					BindingName:      "fox-admin-cluster-admin",
					Scope:            "cluster-wide",
					SubjectKind:      "ServiceAccount",
					SubjectNamespace: stringPtr("default"),
					SubjectName:      "fox-admin",
					DangerousRights:  []string{"admin-like wildcard access"},
					EvidenceStatus:   "direct",
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:default:fox-admin", Namespace: "default", Name: "fox-admin"},
			},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:default:fox-admin", Namespace: "default", Name: "fox-admin", Kind: "Pod", ServiceAccountName: "fox-admin", Privileged: true},
			},
		},
		exposuresData: model.ExposureData{},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildPrivescPayload() error = %v", err)
	}

	rows, ok := payload["escalation_paths"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("escalation_paths = %#v, want posture-only rows", payload["escalation_paths"])
	}

	first := requireMap(t, rows[0])
	if first["path_class"] != "posture-only" {
		t.Fatalf("first path_class = %v, want posture-only", first["path_class"])
	}
	if first["priority"] != "low" {
		t.Fatalf("first priority = %v, want low", first["priority"])
	}
	if !strings.Contains(first["what_is_missing"].(string), "not proven") {
		t.Fatalf("first what_is_missing = %q, want proof-boundary wording", first["what_is_missing"])
	}
}

func TestPrivescTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"privesc"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{"priority", "class", "foothold", "posture-only", "fox-admin"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}
