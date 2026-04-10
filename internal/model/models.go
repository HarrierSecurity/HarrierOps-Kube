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

type WorkloadAction struct {
	Verb            string   `json:"verb"`
	TargetGroup     string   `json:"target_group"`
	TargetResources []string `json:"target_resources"`
	Summary         string   `json:"summary"`
}

type RBACGrant struct {
	ID               string           `json:"id"`
	BindingKind      string           `json:"binding_kind"`
	BindingName      string           `json:"binding_name"`
	Namespace        *string          `json:"namespace"`
	Scope            string           `json:"scope"`
	RoleKind         string           `json:"role_kind"`
	RoleName         string           `json:"role_name"`
	RoleDisplayName  string           `json:"role_display_name"`
	BuiltIn          bool             `json:"built_in"`
	SubjectKind      string           `json:"subject_kind"`
	SubjectName      string           `json:"subject_name"`
	SubjectNamespace *string          `json:"subject_namespace"`
	SubjectDisplay   string           `json:"subject_display"`
	DangerousRights  []string         `json:"dangerous_rights"`
	WorkloadActions  []WorkloadAction `json:"workload_actions,omitempty"`
	RelatedWorkloads []string         `json:"related_workloads"`
	WorkloadCount    int              `json:"workload_count"`
	EvidenceStatus   string           `json:"evidence_status"`
	Priority         string           `json:"priority"`
	WhyCare          string           `json:"why_care"`
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
	PowerRank            int      `json:"-"`
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
	Command                      []string `json:"command"`
	Args                         []string `json:"args"`
	EnvNames                     []string `json:"env"`
	MountedSecretRefs            []string `json:"mounted_secret_refs"`
	MountedConfigRefs            []string `json:"mounted_config_refs"`
	InitContainers               []string `json:"init_containers"`
	Sidecars                     []string `json:"sidecars"`
	Replicas                     *int     `json:"replicas,omitempty"`
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
	ID                   string   `json:"id"`
	Kind                 string   `json:"kind"`
	Name                 string   `json:"name"`
	Namespace            string   `json:"namespace"`
	ServiceAccountName   string   `json:"service_account_name"`
	IdentitySummary      string   `json:"identity_summary"`
	ServiceAccountPower  string   `json:"service_account_power"`
	Images               []string `json:"images"`
	VisiblePatchSurfaces []string `json:"visible_patch_surfaces"`
	RelatedExposures     []string `json:"related_exposures"`
	PublicExposure       bool     `json:"public_exposure"`
	RiskSignals          []string `json:"risk_signals"`
	Priority             string   `json:"priority"`
	WhyCare              string   `json:"why_care"`
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

type PermissionPath struct {
	ID                string   `json:"id"`
	Subject           string   `json:"subject"`
	SubjectConfidence string   `json:"subject_confidence"`
	Scope             string   `json:"scope"`
	ActionVerb        string   `json:"action_verb,omitempty"`
	TargetGroup       string   `json:"target_group,omitempty"`
	TargetResources   []string `json:"target_resources,omitempty"`
	ActionSummary     string   `json:"action_summary"`
	EvidenceStatus    string   `json:"evidence_status"`
	RelatedBindings   []string `json:"related_bindings"`
	Priority          string   `json:"priority"`
	WhyCare           string   `json:"why_care"`
	NextReview        string   `json:"next_review,omitempty"`
}

type SecretPath struct {
	ID                  string   `json:"id"`
	SecretStory         string   `json:"secret_story"`
	SafeLabel           string   `json:"safe_label"`
	SourceSurface       string   `json:"source_surface"`
	Namespace           string   `json:"namespace"`
	Subject             string   `json:"subject"`
	RelatedWorkloads    []string `json:"related_workloads"`
	LikelySecretType    string   `json:"likely_secret_type"`
	LikelyTargetFamily  string   `json:"likely_target_family"`
	Confidence          string   `json:"confidence"`
	DirectUseConfidence string   `json:"direct_use_confidence"`
	TrustPath           string   `json:"trust_path"`
	OperatorSignal      string   `json:"operator_signal"`
	Priority            string   `json:"priority"`
	WhyCare             string   `json:"why_care"`
	NextReview          string   `json:"next_review,omitempty"`
}

type PrivescPath struct {
	ID                string `json:"id"`
	StartingFoothold  string `json:"starting_foothold"`
	SubjectConfidence string `json:"subject_confidence"`
	PathClass         string `json:"path_class"`
	Action            string `json:"action"`
	StrongerOutcome   string `json:"stronger_outcome"`
	OutcomePower      string `json:"outcome_power,omitempty"`
	Confidence        string `json:"confidence"`
	OperatorSignal    string `json:"operator_signal"`
	Priority          string `json:"priority"`
	WhatIsProven      string `json:"what_is_proven"`
	WhatIsMissing     string `json:"what_is_missing"`
	WhyCare           string `json:"why_care"`
	NextReview        string `json:"next_review,omitempty"`
}

type ChainSourceDescriptor struct {
	Command       string   `json:"command"`
	MinimumFields []string `json:"minimum_fields"`
	Rationale     string   `json:"rationale"`
}

type ChainFamilyDescriptor struct {
	Family              string                  `json:"family"`
	State               string                  `json:"state"`
	Meaning             string                  `json:"meaning"`
	Summary             string                  `json:"summary"`
	AllowedClaim        string                  `json:"allowed_claim"`
	CurrentGap          string                  `json:"current_gap"`
	BestCurrentExamples []string                `json:"best_current_examples"`
	PlannedRowShape     []string                `json:"planned_row_shape"`
	PathTypeGuide       []ChainPathTypeGuide    `json:"path_type_guide"`
	InternalProofLadder []ChainProofState       `json:"internal_proof_ladder"`
	SourceCommands      []ChainSourceDescriptor `json:"source_commands"`
}

type ChainPathTypeGuide struct {
	Name              string `json:"name"`
	Meaning           string `json:"meaning"`
	DefaultNextReview string `json:"default_next_review"`
	PriorityIntent    string `json:"priority_intent"`
}

type ChainProofState struct {
	State   string `json:"state"`
	Meaning string `json:"meaning"`
}

type ChainPathRecord struct {
	ChainID                 string   `json:"chain_id"`
	Priority                string   `json:"priority"`
	InternalProofState      string   `json:"internal_proof_state,omitempty"`
	VisibilityTier          string   `json:"visibility_tier,omitempty"`
	PathType                string   `json:"path_type"`
	StartingFoothold        string   `json:"starting_foothold"`
	SourceAsset             string   `json:"source_asset"`
	SourceNamespace         string   `json:"source_namespace,omitempty"`
	SubversionPoint         string   `json:"subversion_point"`
	LikelyKubernetesControl string   `json:"likely_kubernetes_control"`
	Urgency                 string   `json:"urgency,omitempty"`
	WhyStopHere             string   `json:"why_stop_here"`
	ConfidenceBoundary      string   `json:"confidence_boundary"`
	NextReview              string   `json:"next_review"`
	Summary                 string   `json:"summary"`
	MissingConfirmation     string   `json:"missing_confirmation,omitempty"`
	EvidenceCommands        []string `json:"evidence_commands"`
	RelatedIDs              []string `json:"related_ids"`
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

type PermissionsOutput struct {
	Metadata    contracts.Metadata `json:"metadata"`
	Permissions []PermissionPath   `json:"permissions"`
	Issues      []Issue            `json:"issues"`
}

type SecretsOutput struct {
	Metadata    contracts.Metadata `json:"metadata"`
	SecretPaths []SecretPath       `json:"secret_paths"`
	Issues      []Issue            `json:"issues"`
}

type PrivescOutput struct {
	Metadata   contracts.Metadata `json:"metadata"`
	Escalation []PrivescPath      `json:"escalation_paths"`
	Issues     []Issue            `json:"issues"`
}

type ChainsScaffoldOutput struct {
	Metadata               contracts.Metadata      `json:"metadata"`
	GroupedCommandName     string                  `json:"grouped_command_name"`
	CommandState           string                  `json:"command_state"`
	CurrentBehavior        string                  `json:"current_behavior"`
	PlannedInputModes      []string                `json:"planned_input_modes"`
	PreferredArtifactOrder []string                `json:"preferred_artifact_order"`
	SelectedFamily         *string                 `json:"selected_family,omitempty"`
	Families               []ChainFamilyDescriptor `json:"families"`
	Issues                 []Issue                 `json:"issues"`
}

type ChainsOutput struct {
	Metadata           contracts.Metadata `json:"metadata"`
	GroupedCommandName string             `json:"grouped_command_name"`
	Family             string             `json:"family"`
	InputMode          string             `json:"input_mode"`
	CommandState       string             `json:"command_state"`
	Summary            string             `json:"summary"`
	ClaimBoundary      string             `json:"claim_boundary"`
	BackingCommands    []string           `json:"backing_commands"`
	Paths              []ChainPathRecord  `json:"paths"`
	Issues             []Issue            `json:"issues"`
}
