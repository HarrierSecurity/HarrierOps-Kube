package app

import (
	"harrierops-kube/internal/chains"
	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildChainsPayload(selectedFamily string, options Options) (map[string]any, error) {
	if selectedFamily == "" {
		return buildChainsScaffoldPayload(selectedFamily)
	}

	spec, ok := chains.FamilySpecFor(selectedFamily)
	if !ok || spec.State != "implemented" {
		return buildChainsScaffoldPayload(selectedFamily)
	}

	factProvider, err := provider.NewFixtureProvider(options.FixtureDir)
	if err != nil {
		return nil, err
	}

	query := provider.QueryOptions{
		ContextName: options.Context,
		Namespace:   options.Namespace,
	}
	return buildSelectedChainPayload(factProvider, query, selectedFamily)
}

func buildChainsScaffoldPayload(selectedFamily string) (map[string]any, error) {
	output, err := chains.BuildScaffoldOutput(buildMetadata(chains.GroupedCommandName, model.MetadataContext{}, ""), selectedFamily)
	if err != nil {
		return nil, err
	}
	return structToMap(output)
}

func buildSelectedChainPayload(factProvider provider.Provider, query provider.QueryOptions, selectedFamily string) (map[string]any, error) {
	metadataContext, metadataIssue := loadMetadataContextForChains(factProvider, query)
	whoamiData, whoamiIssue := loadWhoAmIForChains(factProvider, query)
	workloadData, workloadIssue := loadWorkloadsSupportForChains(factProvider, query)
	serviceAccountData, serviceAccountIssue := loadServiceAccountsSupportForChains(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForChains(factProvider, query)
	rbacData, rbacIssue := loadRBACSupportForChains(factProvider, query)

	workloadRows := enrichWorkloadPaths(workloadData, serviceAccountData, exposureData, rbacData)
	serviceAccountRows := enrichServiceAccountPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	permissionRows, permissionIssues := derivePermissionPaths(whoamiData.CurrentIdentity, rbacData.RoleGrants)
	if permissionRows == nil {
		permissionRows = []model.PermissionPath{}
	}
	secretRows := enrichSecretPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)

	issues := append([]model.Issue{}, whoamiData.Issues...)
	issues = append(issues, workloadData.Issues...)
	issues = append(issues, serviceAccountData.Issues...)
	issues = append(issues, exposureData.Issues...)
	issues = append(issues, rbacData.Issues...)
	issues = append(issues, permissionIssues...)
	issues = appendIssueIfPresent(issues, metadataIssue)
	issues = appendIssueIfPresent(issues, whoamiIssue)
	issues = appendIssueIfPresent(issues, workloadIssue)
	issues = appendIssueIfPresent(issues, serviceAccountIssue)
	issues = appendIssueIfPresent(issues, exposureIssue)
	issues = appendIssueIfPresent(issues, rbacIssue)

	metadata := buildMetadata(chains.GroupedCommandName, metadataContext, metadataContext.ClusterName)

	switch selectedFamily {
	case "workload-identity-pivot":
		output, err := chains.BuildWorkloadIdentityPivotOutput(metadata, chains.WorkloadIdentityPivotInputs{
			StartingFoothold: currentFootholdLabel(whoamiData.CurrentIdentity),
			Workloads:        workloadRows,
			ServiceAccounts:  serviceAccountRows,
			Permissions:      permissionRows,
			Secrets:          secretRows,
			Issues:           issues,
		})
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	default:
		output, err := chains.BuildScaffoldOutput(metadata, selectedFamily)
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	}
}

func loadMetadataContextForChains(factProvider provider.Provider, query provider.QueryOptions) (model.MetadataContext, *model.Issue) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err == nil {
		return metadataContext, nil
	}
	return model.MetadataContext{}, &model.Issue{
		Kind:    "collection",
		Scope:   "chains.metadata",
		Message: "Grouped chain view could not load metadata context, so command metadata may be incomplete.",
	}
}

func loadWhoAmIForChains(factProvider provider.Provider, query provider.QueryOptions) (model.WhoAmIData, *model.Issue) {
	data, err := factProvider.WhoAmI(query)
	if err == nil {
		return data, nil
	}
	return model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "unknown current identity",
				Kind:       "Unknown",
				Confidence: "blocked",
			},
		}, &model.Issue{
			Kind:    "collection",
			Scope:   "chains.whoami",
			Message: "Grouped chain view could not load current-foothold identity data, so current-session path attribution may be understated.",
		}
}

func loadWorkloadsSupportForChains(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "chains.workloads",
		Message: "Grouped chain view could not load workload support data, so workload-linked path rows may be understated.",
	}
}

func loadServiceAccountsSupportForChains(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "chains.service-accounts",
		Message: "Grouped chain view could not load service-account support data, so attached identity paths may be understated.",
	}
}

func loadExposuresSupportForChains(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "chains.exposure",
		Message: "Grouped chain view could not load exposure support data, so reachable workload context may be understated.",
	}
}

func loadRBACSupportForChains(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "chains.rbac",
		Message: "Grouped chain view could not load RBAC support data, so current-session action edges and stronger identity summaries may be understated.",
	}
}

func appendIssueIfPresent(issues []model.Issue, issue *model.Issue) []model.Issue {
	if issue == nil {
		return issues
	}
	return append(issues, *issue)
}

func scopeLoadIssue(err error, scope string, message string) *model.Issue {
	if err == nil {
		return nil
	}
	return &model.Issue{
		Kind:    "collection",
		Scope:   scope,
		Message: message,
	}
}
