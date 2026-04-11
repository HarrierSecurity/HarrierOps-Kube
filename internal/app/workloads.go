package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildWorkloadsPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	workloadData, err := factProvider.Workloads(query)
	if err != nil {
		return nil, err
	}

	serviceAccountData, serviceAccountIssue := loadServiceAccountsSupportForWorkloads(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForWorkloads(factProvider, query)
	rbacData, rbacIssue := loadRBACSupportForWorkloads(factProvider, query)

	issues := append([]model.Issue{}, workloadData.Issues...)
	issues = append(issues, serviceAccountData.Issues...)
	issues = append(issues, exposureData.Issues...)
	issues = append(issues, rbacData.Issues...)
	if serviceAccountIssue != nil {
		issues = append(issues, *serviceAccountIssue)
	}
	if exposureIssue != nil {
		issues = append(issues, *exposureIssue)
	}
	if rbacIssue != nil {
		issues = append(issues, *rbacIssue)
	}

	metadata := buildMetadata("workloads", metadataContext, "")
	rows := enrichWorkloadPaths(workloadData, serviceAccountData, exposureData, rbacData)

	return structToMap(model.WorkloadsOutput{
		Metadata:       metadata,
		WorkloadAssets: rows,
		Findings:       workloadData.Findings,
		Issues:         issues,
	})
}

func loadServiceAccountsSupportForWorkloads(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "workloads.service-accounts",
		Message: "Workload triage could not load service-account support data, so identity-path summaries may be understated.",
	}
}

func loadExposuresSupportForWorkloads(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "workloads.exposure",
		Message: "Workload triage could not load exposure support data, so reachable workload paths may be understated.",
	}
}

func loadRBACSupportForWorkloads(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "workloads.rbac",
		Message: "Workload triage could not load RBAC support data, so stronger identity summaries may be understated.",
	}
}

func enrichWorkloadPaths(
	workloadData model.WorkloadsData,
	serviceAccountData model.ServiceAccountsData,
	exposureData model.ExposureData,
	rbacData model.RBACData,
) []model.WorkloadPath {
	serviceAccountPaths := enrichServiceAccountPaths(
		serviceAccountData.ServiceAccounts,
		workloadData,
		exposureData,
		rbacData,
	)

	serviceAccountPathByKey := map[string]model.ServiceAccountPath{}
	for _, path := range serviceAccountPaths {
		serviceAccountPathByKey[serviceAccountKey(path.Namespace, path.Name)] = path
	}

	workloadsByKey := map[string]model.Workload{}
	workloadsByNamespace := map[string][]model.Workload{}
	workloadCentralityByID := map[string]bool{}
	for _, workload := range workloadData.WorkloadAssets {
		key := relatedWorkloadKey(workload.Namespace, workload.Name)
		workloadsByKey[key] = workload
		workloadsByNamespace[workload.Namespace] = append(workloadsByNamespace[workload.Namespace], workload)
		workloadCentralityByID[workload.ID] = workloadLooksOperationallyCentral(workload)
	}

	exposuresByWorkload := map[string][]model.Exposure{}
	for _, exposure := range exposureData.ExposureAssets {
		matchedWorkloads := matchExposureWorkloads(exposure, workloadsByKey, workloadsByNamespace)
		for _, key := range matchedWorkloads.Labels {
			exposuresByWorkload[key] = append(exposuresByWorkload[key], exposure)
		}
	}

	rows := make([]model.WorkloadPath, 0, len(workloadData.WorkloadAssets))
	for _, workload := range workloadData.WorkloadAssets {
		workloadLabel := workload.Namespace + "/" + workload.Name
		serviceAccountPath := serviceAccountPathByKey[serviceAccountKey(workload.Namespace, workload.ServiceAccountName)]
		exposures := exposuresByWorkload[workloadLabel]

		relatedExposures, publicExposure := summarizeWorkloadExposures(exposures)
		riskSignals := model.WorkloadRiskSignals(workload)
		identitySummary := deriveWorkloadIdentitySummary(workload, serviceAccountPath)
		score := workloadPathScore(workload, serviceAccountPath, publicExposure, len(exposures), len(riskSignals))

		visiblePatchSurfaces := visibleWorkloadPatchSurfaces(workload)
		rows = append(rows, model.WorkloadPath{
			ID:                   workload.ID,
			Kind:                 workload.Kind,
			Name:                 workload.Name,
			Namespace:            workload.Namespace,
			ServiceAccountName:   workload.ServiceAccountName,
			IdentitySummary:      identitySummary,
			ServiceAccountPower:  serviceAccountPath.PowerSummary,
			Images:               workload.Images,
			PatchRelevantFields:  append([]string(nil), visiblePatchSurfaces...),
			VisiblePatchSurfaces: append([]string(nil), visiblePatchSurfaces...),
			RelatedExposures:     relatedExposures,
			PublicExposure:       publicExposure,
			RiskSignals:          riskSignals,
			Priority:             semanticPriority(score),
			WhyCare:              deriveWorkloadWhyCare(workload, serviceAccountPath, relatedExposures, publicExposure, riskSignals),
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		leftPriority := priorityOrder(rows[i].Priority)
		rightPriority := priorityOrder(rows[j].Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if rows[i].PublicExposure != rows[j].PublicExposure {
			return rows[i].PublicExposure
		}
		if len(rows[i].RiskSignals) != len(rows[j].RiskSignals) {
			return len(rows[i].RiskSignals) > len(rows[j].RiskSignals)
		}
		leftCentral := workloadCentralityByID[rows[i].ID]
		rightCentral := workloadCentralityByID[rows[j].ID]
		if leftCentral != rightCentral {
			return leftCentral
		}
		if rows[i].ServiceAccountPower != rows[j].ServiceAccountPower {
			return rows[i].ServiceAccountPower > rows[j].ServiceAccountPower
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		return rows[i].Name < rows[j].Name
	})

	return rows
}

func summarizeWorkloadExposures(exposures []model.Exposure) ([]string, bool) {
	if len(exposures) == 0 {
		return []string{}, false
	}

	summaries := make([]string, 0, len(exposures))
	publicExposure := false
	for _, exposure := range exposures {
		label := exposure.ExposureType
		if len(exposure.ExternalTargets) > 0 {
			label += " " + strings.Join(exposure.ExternalTargets, ", ")
		}
		summaries = append(summaries, label)
		if exposure.Public {
			publicExposure = true
		}
	}
	sort.Strings(summaries)
	return summaries, publicExposure
}

func visibleWorkloadPatchSurfaces(workload model.Workload) []string {
	surfaces := []string{}
	if len(workload.Images) > 0 {
		surfaces = append(surfaces, "image")
	}
	if len(workload.Command) > 0 {
		surfaces = append(surfaces, "command")
	}
	if len(workload.Args) > 0 {
		surfaces = append(surfaces, "args")
	}
	if len(workload.EnvNames) > 0 {
		surfaces = append(surfaces, "env")
	}
	if workload.ServiceAccountName != "" {
		surfaces = append(surfaces, "service account")
	}
	if len(workload.MountedSecretRefs) > 0 {
		surfaces = append(surfaces, "mounted secret refs")
	}
	if len(workload.MountedConfigRefs) > 0 {
		surfaces = append(surfaces, "mounted config refs")
	}
	if len(workload.InitContainers) > 0 {
		surfaces = append(surfaces, "init containers")
	}
	if len(workload.Sidecars) > 0 {
		surfaces = append(surfaces, "sidecars")
	}
	return surfaces
}

func deriveWorkloadIdentitySummary(workload model.Workload, serviceAccountPath model.ServiceAccountPath) string {
	identityLabel := workload.Namespace + "/" + workload.ServiceAccountName
	if serviceAccountPath.PowerSummary != "" {
		return fmt.Sprintf("runs as %s (%s)", identityLabel, serviceAccountPath.PowerSummary)
	}
	if workload.ServiceAccountName == "" {
		return "current scope does not confirm the attached service account"
	}
	return fmt.Sprintf("runs as %s", identityLabel)
}

func workloadPathScore(workload model.Workload, serviceAccountPath model.ServiceAccountPath, publicExposure bool, exposureCount int, riskSignalCount int) int {
	score := 0
	if publicExposure {
		score += 40
	}
	if exposureCount > 0 {
		score += 20
	}
	if serviceAccountPath.PowerSummary != "" {
		score += 30
	}
	if workload.ServiceAccountName != "" && workload.ServiceAccountName != "default" {
		score += 10
	}
	score += riskSignalCount * 8
	if workload.Privileged {
		score += 20
	}
	if workload.DockerSocketMount {
		score += 20
	}
	if workload.HostNetwork || workload.HostPID || workload.HostIPC {
		score += 15
	}
	if len(workload.HostPathMounts) > 0 {
		score += 15
	}
	if workload.AllowPrivilegeEscalation {
		score += 10
	}
	if workload.AutomountServiceAccountToken != nil && *workload.AutomountServiceAccountToken {
		score += 5
	}
	if workloadLooksOperationallyCentral(workload) {
		score += 12
	}
	return score
}

func deriveWorkloadWhyCare(workload model.Workload, serviceAccountPath model.ServiceAccountPath, exposures []string, publicExposure bool, riskSignals []string) string {
	reasons := []string{}
	if publicExposure {
		reasons = append(reasons, "has a public-looking exposure path")
	} else if len(exposures) > 0 {
		reasons = append(reasons, "has a visible exposure path")
	}
	if serviceAccountPath.PowerSummary != "" {
		reasons = append(reasons, serviceAccountPath.PowerSummary)
	} else if workload.ServiceAccountName != "" && workload.ServiceAccountName != "default" {
		reasons = append(reasons, "runs as a named service account")
	}
	if len(riskSignals) > 0 {
		reasons = append(reasons, model.WorkloadWhyCareRiskPhrase(riskSignals[0]))
	}
	if workloadLooksOperationallyCentral(workload) {
		reasons = append(reasons, "looks operationally central")
	}
	if len(reasons) > 0 {
		return fmt.Sprintf("Workload rises because it %s.", strings.Join(reasons, ", "))
	}
	if workload.ServiceAccountName != "" {
		return "Workload stays visible because it still grounds a workload-to-identity path."
	}
	return "Workload stays visible because it still grounds running execution context."
}
