package model

import "harrierops-kube/internal/contracts"

type MetadataContext struct {
	ContextName   string
	ClusterName   string
	Namespace     string
	DockerContext string
}

type Issue struct {
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	RelatedIDs  []string `json:"related_ids"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
}

type KubeContext struct {
	CurrentContext string `json:"current_context"`
	ClusterName    string `json:"cluster_name"`
	User           string `json:"user"`
	Namespace      string `json:"namespace"`
	Server         string `json:"server"`
	ServerVersion  string `json:"server_version"`
}

type CurrentIdentity struct {
	Label      string  `json:"label"`
	Kind       string  `json:"kind"`
	Namespace  *string `json:"namespace,omitempty"`
	Confidence string  `json:"confidence"`
}

type SessionProfile struct {
	AuthMaterialType string `json:"auth_material_type"`
	ExecutionOrigin  string `json:"execution_origin"`
	FootholdFamily   string `json:"foothold_family"`
	VisibilityScope  string `json:"visibility_scope"`
}

type DockerSession struct {
	Available   bool   `json:"available"`
	ContextName string `json:"context_name"`
}

type WhoAmIData struct {
	KubeContext        KubeContext        `json:"kube_context"`
	CurrentIdentity    CurrentIdentity    `json:"current_identity"`
	Session            SessionProfile     `json:"session"`
	EnvironmentHint    EnvironmentSummary `json:"environment_hint"`
	IdentityEvidence   []string           `json:"identity_evidence"`
	VisibilityBlockers []string           `json:"visibility_blockers"`
	Docker             *DockerSession     `json:"docker,omitempty"`
	Issues             []Issue            `json:"issues"`
}

type InventoryData struct {
	KubernetesCounts map[string]int `json:"kubernetes_counts"`
	DockerCounts     map[string]int `json:"docker_counts,omitempty"`
	Issues           []Issue        `json:"issues"`
}

type VisibilitySummary struct {
	Scope      string `json:"scope"`
	Assessment string `json:"assessment"`
	Summary    string `json:"summary"`
}

type EnvironmentSummary struct {
	Type       string   `json:"type"`
	Confidence string   `json:"confidence"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence"`
}

type ExposureFootprint struct {
	PublicPaths      int    `json:"public_paths"`
	Ingresses        int    `json:"ingresses"`
	LoadBalancers    int    `json:"load_balancers"`
	NodePorts        int    `json:"node_ports"`
	HostExposurePods int    `json:"host_exposure_pods"`
	Summary          string `json:"summary"`
}

type RiskyWorkloadFootprint struct {
	PrivilegedWorkloads    int    `json:"privileged_workloads"`
	HostTouchingWorkloads  int    `json:"host_touching_workloads"`
	HostNamespaceWorkloads int    `json:"host_namespace_workloads"`
	DockerSocketWorkloads  int    `json:"docker_socket_workloads"`
	Summary                string `json:"summary"`
}

type IdentityFootprint struct {
	ServiceAccounts           int    `json:"service_accounts"`
	RoleGrants                int    `json:"role_grants"`
	ClusterWideRoleGrants     int    `json:"cluster_wide_role_grants"`
	HighImpactServiceAccounts int    `json:"high_impact_service_accounts"`
	Summary                   string `json:"summary"`
}

type NextCommandHint struct {
	Command string `json:"command"`
	Why     string `json:"why"`
}

type RBACGrant struct {
	ID               string   `json:"id"`
	BindingKind      string   `json:"binding_kind"`
	BindingName      string   `json:"binding_name"`
	Namespace        *string  `json:"namespace"`
	Scope            string   `json:"scope"`
	RoleKind         string   `json:"role_kind"`
	RoleName         string   `json:"role_name"`
	RoleDisplayName  string   `json:"role_display_name"`
	BuiltIn          bool     `json:"built_in"`
	SubjectKind      string   `json:"subject_kind"`
	SubjectName      string   `json:"subject_name"`
	SubjectNamespace *string  `json:"subject_namespace"`
	SubjectDisplay   string   `json:"subject_display"`
	DangerousRights  []string `json:"dangerous_rights"`
	RelatedWorkloads []string `json:"related_workloads"`
	WorkloadCount    int      `json:"workload_count"`
	EvidenceStatus   string   `json:"evidence_status"`
	Priority         string   `json:"priority"`
	WhyCare          string   `json:"why_care"`
}

type RBACData struct {
	RoleGrants []RBACGrant `json:"role_grants"`
	Issues     []Issue     `json:"issues"`
}

type ServiceAccount struct {
	ID                           string   `json:"id"`
	Name                         string   `json:"name"`
	Namespace                    string   `json:"namespace"`
	AutomountServiceAccountToken *bool    `json:"automount_service_account_token,omitempty"`
	BoundRoles                   []string `json:"bound_roles"`
	ImagePullSecrets             []string `json:"image_pull_secrets"`
	SecretNames                  []string `json:"secret_names"`
}

type ServiceAccountsData struct {
	ServiceAccounts []ServiceAccount `json:"service_accounts"`
	Findings        []Finding        `json:"findings"`
	Issues          []Issue          `json:"issues"`
}

type ServiceAccountPath struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Namespace            string   `json:"namespace"`
	BoundRoles           []string `json:"bound_roles"`
	RelatedWorkloads     []string `json:"related_workloads"`
	WorkloadCount        int      `json:"workload_count"`
	ExposedWorkloads     []string `json:"exposed_workloads"`
	ExposedWorkloadCount int      `json:"exposed_workload_count"`
	RiskyWorkloads       []string `json:"risky_workloads"`
	RiskyWorkloadCount   int      `json:"risky_workload_count"`
	EvidenceStatus       string   `json:"evidence_status"`
	Priority             string   `json:"priority"`
	PowerSummary         string   `json:"power_summary"`
	TokenPosture         string   `json:"token_posture"`
	WhyCare              string   `json:"why_care"`
}

type Workload struct {
	ID                           string   `json:"id"`
	Kind                         string   `json:"kind"`
	Name                         string   `json:"name"`
	Namespace                    string   `json:"namespace"`
	ServiceAccountName           string   `json:"service_account_name"`
	Images                       []string `json:"images"`
	Privileged                   bool     `json:"privileged"`
	AllowPrivilegeEscalation     bool     `json:"allow_privilege_escalation"`
	RunsAsRoot                   bool     `json:"runs_as_root"`
	AddedCapabilities            []string `json:"added_capabilities"`
	HostPathMounts               []string `json:"host_path_mounts"`
	DockerSocketMount            bool     `json:"docker_socket_mount"`
	HostNetwork                  bool     `json:"host_network"`
	HostPID                      bool     `json:"host_pid"`
	HostIPC                      bool     `json:"host_ipc"`
	AutomountServiceAccountToken *bool    `json:"automount_service_account_token,omitempty"`
	SeccompProfile               *string  `json:"seccomp_profile"`
}

type WorkloadsData struct {
	WorkloadAssets []Workload `json:"workload_assets"`
	Findings       []Finding  `json:"findings"`
	Issues         []Issue    `json:"issues"`
}

type WorkloadPath struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind"`
	Name                string   `json:"name"`
	Namespace           string   `json:"namespace"`
	ServiceAccountName  string   `json:"service_account_name"`
	IdentitySummary     string   `json:"identity_summary"`
	ServiceAccountPower string   `json:"service_account_power"`
	Images              []string `json:"images"`
	RelatedExposures    []string `json:"related_exposures"`
	PublicExposure      bool     `json:"public_exposure"`
	RiskSignals         []string `json:"risk_signals"`
	Priority            string   `json:"priority"`
	WhyCare             string   `json:"why_care"`
}

type Exposure struct {
	ID               string   `json:"id"`
	AssetType        string   `json:"asset_type"`
	ExposureType     string   `json:"exposure_type"`
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	Public           bool     `json:"public"`
	ExternalTargets  []string `json:"external_targets"`
	RelatedWorkloads []string `json:"related_workloads"`
}

type ExposureData struct {
	ExposureAssets []Exposure `json:"exposure_assets"`
	Findings       []Finding  `json:"findings"`
	Issues         []Issue    `json:"issues"`
}

type ExposurePath struct {
	ID                string   `json:"id"`
	AssetType         string   `json:"asset_type"`
	ExposureType      string   `json:"exposure_type"`
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace"`
	Public            bool     `json:"public"`
	ExternalTargets   []string `json:"external_targets"`
	RelatedWorkloads  []string `json:"related_workloads"`
	AttributionStatus string   `json:"attribution_status"`
	IdentitySummary   string   `json:"identity_summary"`
	BackendSignal     string   `json:"backend_signal"`
	Priority          string   `json:"priority"`
	WhyCare           string   `json:"why_care"`
}

type WhoAmIOutput struct {
	Metadata           contracts.Metadata `json:"metadata"`
	KubeContext        KubeContext        `json:"kube_context"`
	CurrentIdentity    CurrentIdentity    `json:"current_identity"`
	Session            SessionProfile     `json:"session"`
	EnvironmentHint    EnvironmentSummary `json:"environment_hint"`
	IdentityEvidence   []string           `json:"identity_evidence"`
	VisibilityBlockers []string           `json:"visibility_blockers"`
	Issues             []Issue            `json:"issues"`
}

type InventoryOutput struct {
	Metadata               contracts.Metadata     `json:"metadata"`
	Visibility             VisibilitySummary      `json:"visibility"`
	Environment            EnvironmentSummary     `json:"environment"`
	ExposureFootprint      ExposureFootprint      `json:"exposure_footprint"`
	RiskyWorkloadFootprint RiskyWorkloadFootprint `json:"risky_workload_footprint"`
	IdentityFootprint      IdentityFootprint      `json:"identity_footprint"`
	NextCommands           []NextCommandHint      `json:"next_commands"`
	KubernetesCounts       map[string]int         `json:"kubernetes_counts"`
	DockerCounts           map[string]int         `json:"docker_counts,omitempty"`
	Issues                 []Issue                `json:"issues"`
}

type RbacOutput struct {
	Metadata   contracts.Metadata `json:"metadata"`
	RoleGrants []RBACGrant        `json:"role_grants"`
	Issues     []Issue            `json:"issues"`
}

type ServiceAccountsOutput struct {
	Metadata        contracts.Metadata   `json:"metadata"`
	ServiceAccounts []ServiceAccountPath `json:"service_accounts"`
	Findings        []Finding            `json:"findings"`
	Issues          []Issue              `json:"issues"`
}

type WorkloadsOutput struct {
	Metadata       contracts.Metadata `json:"metadata"`
	WorkloadAssets []WorkloadPath     `json:"workload_assets"`
	Findings       []Finding          `json:"findings"`
	Issues         []Issue            `json:"issues"`
}

type ExposureOutput struct {
	Metadata       contracts.Metadata `json:"metadata"`
	ExposureAssets []ExposurePath     `json:"exposure_assets"`
	Findings       []Finding          `json:"findings"`
	Issues         []Issue            `json:"issues"`
}
