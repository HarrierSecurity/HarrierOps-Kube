package contracts

import "sort"

const SchemaVersion = "1.0.0"

type Metadata struct {
	Command       string  `json:"command"`
	ContextName   *string `json:"context_name"`
	ClusterName   *string `json:"cluster_name"`
	Namespace     *string `json:"namespace"`
	DockerContext *string `json:"docker_context"`
	GeneratedAt   string  `json:"generated_at"`
	SchemaVersion string  `json:"schema_version"`
}

type CommandContract struct {
	Model          string
	TopLevelFields []string
}

var commandContracts = map[string]CommandContract{
	"whoami": {
		Model:          "WhoAmIOutput",
		TopLevelFields: []string{"metadata", "kube_context", "current_identity", "session", "environment_hint", "identity_evidence", "visibility_blockers", "issues"},
	},
	"inventory": {
		Model:          "InventoryOutput",
		TopLevelFields: []string{"metadata", "visibility", "environment", "exposure_footprint", "risky_workload_footprint", "identity_footprint", "next_commands", "kubernetes_counts", "docker_counts", "issues"},
	},
	"rbac": {
		Model:          "RbacOutput",
		TopLevelFields: []string{"metadata", "role_grants", "issues"},
	},
	"service-accounts": {
		Model:          "ServiceAccountsOutput",
		TopLevelFields: []string{"metadata", "service_accounts", "findings", "issues"},
	},
	"exposure": {
		Model:          "ExposureOutput",
		TopLevelFields: []string{"metadata", "exposure_assets", "findings", "issues"},
	},
	"workloads": {
		Model:          "WorkloadsOutput",
		TopLevelFields: []string{"metadata", "workload_assets", "findings", "issues"},
	},
	"images": {
		Model:          "ImagesOutput",
		TopLevelFields: []string{"metadata", "image_assets", "findings", "issues"},
	},
}

func CommandContractFor(command string) (CommandContract, bool) {
	contract, ok := commandContracts[command]
	return contract, ok
}

func CommandNames() []string {
	names := make([]string, 0, len(commandContracts))
	for name := range commandContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func OptionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
