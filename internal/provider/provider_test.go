package provider

import (
	"path/filepath"
	"testing"

	"harrierops-kube/internal/model"
)

func TestMetadataContextUsesWhoAmIFixtureDefaults(t *testing.T) {
	provider := newFixtureProvider(t)

	metadata, err := provider.MetadataContext(QueryOptions{})
	if err != nil {
		t.Fatalf("MetadataContext() error = %v", err)
	}

	if metadata.ContextName != "lab-cluster" {
		t.Fatalf("ContextName = %q, want lab-cluster", metadata.ContextName)
	}
	if metadata.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", metadata.ClusterName)
	}
	if metadata.Namespace != "default" {
		t.Fatalf("Namespace = %q, want default", metadata.Namespace)
	}
	if metadata.DockerContext != "default" {
		t.Fatalf("DockerContext = %q, want default", metadata.DockerContext)
	}
}

func TestMetadataContextAppliesOverrides(t *testing.T) {
	provider := newFixtureProvider(t)

	metadata, err := provider.MetadataContext(QueryOptions{
		ContextName: "prod-cluster",
		Namespace:   "payments",
	})
	if err != nil {
		t.Fatalf("MetadataContext() error = %v", err)
	}

	if metadata.ContextName != "prod-cluster" {
		t.Fatalf("ContextName = %q, want prod-cluster", metadata.ContextName)
	}
	if metadata.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", metadata.Namespace)
	}
	if metadata.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", metadata.ClusterName)
	}
}

func TestWhoAmIAppliesOverrides(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.WhoAmI(QueryOptions{
		ContextName: "prod-cluster",
		Namespace:   "payments",
	})
	if err != nil {
		t.Fatalf("WhoAmI() error = %v", err)
	}

	if data.KubeContext.CurrentContext != "prod-cluster" {
		t.Fatalf("CurrentContext = %q, want prod-cluster", data.KubeContext.CurrentContext)
	}
	if data.KubeContext.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", data.KubeContext.Namespace)
	}
	if data.KubeContext.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", data.KubeContext.ClusterName)
	}
}

func TestWhoAmILoadsInferredAndBlockedIdentityCases(t *testing.T) {
	testCases := []struct {
		name           string
		fixtureDir     string
		wantConfidence string
		wantLabel      string
	}{
		{
			name:           "inferred",
			fixtureDir:     absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "whoami_cases", "inferred")),
			wantConfidence: "inferred",
			wantLabel:      "system:serviceaccount:payments:api",
		},
		{
			name:           "blocked",
			fixtureDir:     absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "whoami_cases", "blocked")),
			wantConfidence: "blocked",
			wantLabel:      "unknown current identity",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewFixtureProvider(tc.fixtureDir)
			if err != nil {
				t.Fatalf("NewFixtureProvider() error = %v", err)
			}

			data, err := provider.WhoAmI(QueryOptions{})
			if err != nil {
				t.Fatalf("WhoAmI() error = %v", err)
			}

			if data.CurrentIdentity.Confidence != tc.wantConfidence {
				t.Fatalf("CurrentIdentity.Confidence = %q, want %s", data.CurrentIdentity.Confidence, tc.wantConfidence)
			}
			if data.CurrentIdentity.Label != tc.wantLabel {
				t.Fatalf("CurrentIdentity.Label = %q, want %s", data.CurrentIdentity.Label, tc.wantLabel)
			}
		})
	}
}

func TestRBACBindingsDecodeNormalizedGrantRows(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.RBACBindings(QueryOptions{})
	if err != nil {
		t.Fatalf("RBACBindings() error = %v", err)
	}

	if len(data.RoleGrants) != 3 {
		t.Fatalf("len(RoleGrants) = %d, want 3", len(data.RoleGrants))
	}

	first := data.RoleGrants[0]
	if first.RoleDisplayName != "cluster-admin*" {
		t.Fatalf("RoleDisplayName = %q, want cluster-admin*", first.RoleDisplayName)
	}
	if first.Scope != "cluster-wide" {
		t.Fatalf("Scope = %q, want cluster-wide", first.Scope)
	}
	if len(first.DangerousRights) == 0 || first.DangerousRights[0] != "admin-like wildcard access" {
		t.Fatalf("DangerousRights = %#v, want admin-like wildcard access first", first.DangerousRights)
	}

	second := data.RoleGrants[1]
	if !containsWorkloadAction(second.WorkloadActions, "can create pods") {
		t.Fatalf("WorkloadActions = %#v, want can create pods on edit role", second.WorkloadActions)
	}
	if !containsWorkloadAction(second.WorkloadActions, "can patch workload controllers") {
		t.Fatalf("WorkloadActions = %#v, want can patch workload controllers on edit role", second.WorkloadActions)
	}
}

func TestRBACBindingsLiftImpersonateSignals(t *testing.T) {
	provider, err := NewFixtureProvider(absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "rbac_cases", "impersonate")))
	if err != nil {
		t.Fatalf("NewFixtureProvider() error = %v", err)
	}

	data, err := provider.RBACBindings(QueryOptions{})
	if err != nil {
		t.Fatalf("RBACBindings() error = %v", err)
	}
	if len(data.RoleGrants) != 1 {
		t.Fatalf("len(RoleGrants) = %d, want 1", len(data.RoleGrants))
	}
	if !containsString(data.RoleGrants[0].DangerousRights, "impersonate serviceaccounts") {
		t.Fatalf("DangerousRights = %#v, want impersonate serviceaccounts", data.RoleGrants[0].DangerousRights)
	}
}

func TestRBACBindingsKeepVisibleGrantWhenRoleRulesAreBlocked(t *testing.T) {
	provider, err := NewFixtureProvider(absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "rbac_cases", "partial_read")))
	if err != nil {
		t.Fatalf("NewFixtureProvider() error = %v", err)
	}

	data, err := provider.RBACBindings(QueryOptions{})
	if err != nil {
		t.Fatalf("RBACBindings() error = %v", err)
	}
	if len(data.RoleGrants) != 1 {
		t.Fatalf("len(RoleGrants) = %d, want 1", len(data.RoleGrants))
	}
	if data.RoleGrants[0].EvidenceStatus != "visibility blocked" {
		t.Fatalf("EvidenceStatus = %q, want visibility blocked", data.RoleGrants[0].EvidenceStatus)
	}
	if len(data.Issues) == 0 {
		t.Fatalf("expected partial-read issue to be surfaced")
	}
}

func TestServiceAccountsLoadFixtureFindings(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.ServiceAccounts(QueryOptions{})
	if err != nil {
		t.Fatalf("ServiceAccounts() error = %v", err)
	}

	if len(data.Findings) != 3 {
		t.Fatalf("len(Findings) = %d, want 3", len(data.Findings))
	}
	if data.Findings[0].Title == "" {
		t.Fatalf("first finding title is empty")
	}
}

func TestWorkloadsDecodeVisiblePatchSurfaceFields(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.Workloads(QueryOptions{})
	if err != nil {
		t.Fatalf("Workloads() error = %v", err)
	}
	if len(data.WorkloadAssets) == 0 {
		t.Fatal("WorkloadAssets = empty, want fixture rows")
	}

	foxAdmin := data.WorkloadAssets[0]
	if len(foxAdmin.Command) == 0 || foxAdmin.Command[0] != "/bin/sh" {
		t.Fatalf("Command = %#v, want /bin/sh first", foxAdmin.Command)
	}
	if len(foxAdmin.Args) == 0 || foxAdmin.Args[0] != "-c" {
		t.Fatalf("Args = %#v, want -c first", foxAdmin.Args)
	}
	if len(foxAdmin.EnvNames) == 0 || foxAdmin.EnvNames[0] != "AZURE_CLIENT_ID" {
		t.Fatalf("EnvNames = %#v, want AZURE_CLIENT_ID first", foxAdmin.EnvNames)
	}
	if len(foxAdmin.MountedSecretRefs) == 0 || foxAdmin.MountedSecretRefs[0] != "fox-admin-token" {
		t.Fatalf("MountedSecretRefs = %#v, want fox-admin-token first", foxAdmin.MountedSecretRefs)
	}
	if len(foxAdmin.MountedConfigRefs) == 0 || foxAdmin.MountedConfigRefs[0] != "fox-admin-config" {
		t.Fatalf("MountedConfigRefs = %#v, want fox-admin-config first", foxAdmin.MountedConfigRefs)
	}
	if len(foxAdmin.InitContainers) == 0 || foxAdmin.InitContainers[0] != "init-permissions" {
		t.Fatalf("InitContainers = %#v, want init-permissions first", foxAdmin.InitContainers)
	}
	if len(foxAdmin.Sidecars) == 0 || foxAdmin.Sidecars[0] != "log-shipper" {
		t.Fatalf("Sidecars = %#v, want log-shipper first", foxAdmin.Sidecars)
	}
}

func newFixtureProvider(t *testing.T) Provider {
	t.Helper()

	fixtureDir := absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "lab_cluster"))
	provider, err := NewFixtureProvider(fixtureDir)
	if err != nil {
		t.Fatalf("NewFixtureProvider() error = %v", err)
	}
	return provider
}

func absPath(t *testing.T, path string) string {
	t.Helper()

	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(): %v", err)
	}
	return absolute
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsWorkloadAction(values []model.WorkloadAction, want string) bool {
	for _, value := range values {
		if value.Summary == want {
			return true
		}
	}
	return false
}
