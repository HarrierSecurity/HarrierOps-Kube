package app

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildExposurePayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	exposureData, err := factProvider.Exposures(query)
	if err != nil {
		return nil, err
	}

	workloadData, workloadIssue := loadWorkloadsSupportForExposure(factProvider, query)
	serviceAccountData, serviceAccountIssue := loadServiceAccountsSupportForExposure(factProvider, query)
	rbacData, rbacIssue := loadRBACSupportForExposure(factProvider, query)

	issues := append([]model.Issue{}, exposureData.Issues...)
	issues = append(issues, workloadData.Issues...)
	issues = append(issues, serviceAccountData.Issues...)
	issues = append(issues, rbacData.Issues...)
	if workloadIssue != nil {
		issues = append(issues, *workloadIssue)
	}
	if serviceAccountIssue != nil {
		issues = append(issues, *serviceAccountIssue)
	}
	if rbacIssue != nil {
		issues = append(issues, *rbacIssue)
	}

	rows := enrichExposurePaths(exposureData, workloadData, serviceAccountData, rbacData)
	metadata := buildMetadata("exposure", metadataContext, "")

	return structToMap(model.ExposureOutput{
		Metadata:       metadata,
		ExposureAssets: rows,
		Findings:       exposureData.Findings,
		Issues:         issues,
	})
}

func loadWorkloadsSupportForExposure(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "exposure.workloads",
		Message: "Exposure triage could not load workload support data, so backend attribution may be understated.",
	}
}

func loadServiceAccountsSupportForExposure(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "exposure.service-accounts",
		Message: "Exposure triage could not load service-account support data, so backend identity summaries may be understated.",
	}
}

func loadRBACSupportForExposure(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "exposure.rbac",
		Message: "Exposure triage could not load RBAC support data, so stronger backend consequence may be understated.",
	}
}

func enrichExposurePaths(
	exposureData model.ExposureData,
	workloadData model.WorkloadsData,
	serviceAccountData model.ServiceAccountsData,
	rbacData model.RBACData,
) []model.ExposurePath {
	type rankedExposurePath struct {
		path model.ExposurePath
		attr exposureAttribution
	}

	serviceAccountPaths := enrichServiceAccountPaths(
		serviceAccountData.ServiceAccounts,
		workloadData,
		exposureData,
		rbacData,
	)

	serviceAccountByKey := map[string]model.ServiceAccountPath{}
	for _, path := range serviceAccountPaths {
		serviceAccountByKey[serviceAccountKey(path.Namespace, path.Name)] = path
	}

	workloadsByKey := map[string]model.Workload{}
	workloadsByNamespace := map[string][]model.Workload{}
	for _, workload := range workloadData.WorkloadAssets {
		key := relatedWorkloadKey(workload.Namespace, workload.Name)
		workloadsByKey[key] = workload
		workloadsByNamespace[workload.Namespace] = append(workloadsByNamespace[workload.Namespace], workload)
	}

	rows := make([]rankedExposurePath, 0, len(exposureData.ExposureAssets))
	for _, exposure := range exposureData.ExposureAssets {
		attr := attributeExposure(exposure, workloadsByKey, workloadsByNamespace, serviceAccountByKey)
		score := exposurePathScore(exposure, attr)
		rows = append(rows, rankedExposurePath{
			path: model.ExposurePath{
				ID:                exposure.ID,
				AssetType:         exposure.AssetType,
				ExposureType:      exposure.ExposureType,
				Name:              exposure.Name,
				Namespace:         exposure.Namespace,
				Public:            exposure.Public,
				ExternalTargets:   exposure.ExternalTargets,
				RelatedWorkloads:  attr.Workloads,
				AttributionStatus: attr.Status,
				IdentitySummary:   attr.IdentitySummary,
				BackendSignal:     attr.BackendSignal,
				Priority:          semanticPriority(score),
				WhyCare:           deriveExposureWhyCare(exposure, attr),
			},
			attr: attr,
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		leftPriority := priorityOrder(rows[i].path.Priority)
		rightPriority := priorityOrder(rows[j].path.Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if rows[i].path.Public != rows[j].path.Public {
			return rows[i].path.Public
		}
		if attributionOrder(rows[i].path.AttributionStatus) != attributionOrder(rows[j].path.AttributionStatus) {
			return attributionOrder(rows[i].path.AttributionStatus) < attributionOrder(rows[j].path.AttributionStatus)
		}
		if exposureConsequenceOrder(rows[i].attr) != exposureConsequenceOrder(rows[j].attr) {
			return exposureConsequenceOrder(rows[i].attr) > exposureConsequenceOrder(rows[j].attr)
		}
		if exposureTargetClarity(rows[i].path.ExternalTargets) != exposureTargetClarity(rows[j].path.ExternalTargets) {
			return exposureTargetClarity(rows[i].path.ExternalTargets) > exposureTargetClarity(rows[j].path.ExternalTargets)
		}
		if exposureFamilyOrder(rows[i].path.ExposureType) != exposureFamilyOrder(rows[j].path.ExposureType) {
			return exposureFamilyOrder(rows[i].path.ExposureType) < exposureFamilyOrder(rows[j].path.ExposureType)
		}
		if rows[i].path.Namespace != rows[j].path.Namespace {
			return rows[i].path.Namespace < rows[j].path.Namespace
		}
		return rows[i].path.Name < rows[j].path.Name
	})

	ordered := make([]model.ExposurePath, 0, len(rows))
	for _, row := range rows {
		ordered = append(ordered, row.path)
	}
	return ordered
}

type exposureAttribution struct {
	Workloads       []string
	Status          string
	IdentitySummary string
	BackendSignal   string
	PowerSummary    string
	RiskyBackend    bool
	CentralBackend  bool
	ManagementLike  bool
}

func attributeExposure(
	exposure model.Exposure,
	workloadsByKey map[string]model.Workload,
	workloadsByNamespace map[string][]model.Workload,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) exposureAttribution {
	attr := exposureAttribution{
		Workloads:      []string{},
		Status:         "blocked",
		BackendSignal:  "current scope does not confirm the backend workload",
		ManagementLike: looksManagementLike(exposure),
	}

	matchedWorkloads := matchExposureWorkloads(exposure, workloadsByKey, workloadsByNamespace)
	if len(exposure.RelatedWorkloads) > 0 {
		attr.Workloads = matchedWorkloads.Labels
		if len(matchedWorkloads.Matched) > 0 {
			workload := strongestExposureBackend(matchedWorkloads.Matched, serviceAccountByKey)
			attr.Status = "direct"
			attr.IdentitySummary, attr.PowerSummary, attr.RiskyBackend, attr.CentralBackend = summarizeBackendWorkload(workload, serviceAccountByKey)
			if len(matchedWorkloads.Matched) == 1 {
				attr.BackendSignal = "backs " + workload.Namespace + "/" + workload.Name
			} else {
				attr.BackendSignal = fmt.Sprintf("backs %d visible workloads; strongest visible backend is %s/%s", len(matchedWorkloads.Matched), workload.Namespace, workload.Name)
			}
			return attr
		}
		attr.Status = "visibility blocked"
		attr.BackendSignal = "workload name is visible, but current scope does not confirm backend detail"
		return attr
	}

	if matchedWorkloads.Heuristic && len(matchedWorkloads.Matched) == 1 {
		workload := matchedWorkloads.Matched[0]
		attr.Workloads = []string{workload.Namespace + "/" + workload.Name}
		attr.Status = "heuristic"
		attr.IdentitySummary, attr.PowerSummary, attr.RiskyBackend, attr.CentralBackend = summarizeBackendWorkload(workload, serviceAccountByKey)
		attr.BackendSignal = "appears to front " + workload.Namespace + "/" + workload.Name
		return attr
	}

	if attr.ManagementLike {
		attr.Status = "heuristic"
		attr.BackendSignal = "looks management-facing even without strong backend attribution"
	}
	return attr
}

func summarizeBackendWorkload(workload model.Workload, serviceAccountByKey map[string]model.ServiceAccountPath) (string, string, bool, bool) {
	serviceAccountPath := serviceAccountByKey[serviceAccountKey(workload.Namespace, workload.ServiceAccountName)]
	identitySummary := fmt.Sprintf("backend runs as %s/%s", workload.Namespace, workload.ServiceAccountName)
	if serviceAccountPath.PowerSummary != "" {
		identitySummary += " (" + serviceAccountPath.PowerSummary + ")"
	}
	return identitySummary, serviceAccountPath.PowerSummary, model.IsRiskyWorkload(workload), workloadLooksOperationallyCentral(workload)
}

func strongestExposureBackend(workloads []model.Workload, serviceAccountByKey map[string]model.ServiceAccountPath) model.Workload {
	best := workloads[0]
	bestScore := exposureBackendStrength(best, serviceAccountByKey[serviceAccountKey(best.Namespace, best.ServiceAccountName)])

	for _, candidate := range workloads[1:] {
		candidatePath := serviceAccountByKey[serviceAccountKey(candidate.Namespace, candidate.ServiceAccountName)]
		candidateScore := exposureBackendStrength(candidate, candidatePath)
		if candidateScore > bestScore {
			best = candidate
			bestScore = candidateScore
			continue
		}
		if candidateScore == bestScore {
			candidateLabel := candidate.Namespace + "/" + candidate.Name
			bestLabel := best.Namespace + "/" + best.Name
			if candidateLabel < bestLabel {
				best = candidate
				bestScore = candidateScore
			}
		}
	}

	return best
}

func exposureBackendStrength(workload model.Workload, serviceAccountPath model.ServiceAccountPath) int {
	score := 0
	if serviceAccountPath.PowerSummary != "" {
		score += 30
	}
	if model.IsRiskyWorkload(workload) {
		score += 20
	}
	if workloadLooksOperationallyCentral(workload) {
		score += 12
	}
	if workload.ServiceAccountName != "" && workload.ServiceAccountName != "default" {
		score += 5
	}
	return score
}

func heuristicExposureMatches(exposure model.Exposure, workloads []model.Workload) []model.Workload {
	if len(workloads) == 0 {
		return nil
	}
	exposureTokens := normalizedExposureTokens(exposure.Name)
	if len(exposureTokens) == 0 {
		return nil
	}

	bestScore := 0
	candidates := []model.Workload{}
	for _, workload := range workloads {
		score := tokenOverlapScore(exposureTokens, normalizedExposureTokens(workload.Name))
		if score == 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			candidates = []model.Workload{workload}
			continue
		}
		if score == bestScore {
			candidates = append(candidates, workload)
		}
	}
	return candidates
}

func normalizedExposureTokens(value string) []string {
	rawParts := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		switch part {
		case "", "ing", "ingress", "svc", "service", "lb", "loadbalancer", "load", "balancer":
			continue
		default:
			parts = append(parts, part)
		}
	}
	return parts
}

func tokenOverlapScore(left []string, right []string) int {
	rightSet := map[string]struct{}{}
	for _, item := range right {
		rightSet[item] = struct{}{}
	}
	score := 0
	for _, item := range left {
		if _, ok := rightSet[item]; ok {
			score++
		}
	}
	return score
}

func looksManagementLike(exposure model.Exposure) bool {
	candidates := []string{strings.ToLower(exposure.Name)}
	for _, target := range exposure.ExternalTargets {
		candidates = append(candidates, strings.ToLower(target))
	}
	for _, candidate := range candidates {
		for _, marker := range []string{"metrics", "grafana", "prometheus", "argocd", "dashboard", "admin", "jenkins", "kibana"} {
			if strings.Contains(candidate, marker) {
				return true
			}
		}
	}
	return false
}

func exposurePathScore(exposure model.Exposure, attr exposureAttribution) int {
	score := 0
	if exposure.Public {
		score += 45
	}
	if len(exposure.ExternalTargets) > 0 {
		score += 10
	}
	score += maxInt(20-attributionOrder(attr.Status)*5, 0)
	if attr.PowerSummary != "" {
		score += 20
	}
	if attr.RiskyBackend {
		score += 15
	}
	if attr.ManagementLike {
		score += 12
	}
	score += exposureFamilyWeight(exposure.ExposureType)
	return score
}

func deriveExposureWhyCare(exposure model.Exposure, attr exposureAttribution) string {
	reasons := []string{}
	if exposure.Public {
		reasons = append(reasons, "has a public-looking target")
	} else {
		reasons = append(reasons, "exposes a broad workload path")
	}
	switch attr.Status {
	case "direct":
		reasons = append(reasons, attr.BackendSignal)
	case "heuristic":
		reasons = append(reasons, attr.BackendSignal)
		reasons = append(reasons, "backend attribution is heuristic")
	case "visibility blocked":
		reasons = append(reasons, "backend detail is not visible from current credentials")
	}
	if attr.PowerSummary != "" {
		reasons = append(reasons, attr.PowerSummary)
	}
	if attr.CentralBackend {
		reasons = append(reasons, "backs an operationally central workload")
	}
	if attr.ManagementLike && len(attr.Workloads) > 0 {
		reasons = append(reasons, "looks management-facing")
	}
	return fmt.Sprintf("Exposure rises because it %s.", strings.Join(reasons, ", "))
}

func exposureConsequenceOrder(attr exposureAttribution) int {
	score := 0
	if attr.PowerSummary != "" {
		score += 4
	}
	if attr.RiskyBackend {
		score += 2
	}
	if attr.CentralBackend {
		score += 2
	}
	if len(attr.Workloads) > 0 {
		score += 1
	}
	if attr.ManagementLike {
		score += 1
	}
	return score
}

func exposureTargetClarity(targets []string) int {
	best := 0
	for _, target := range targets {
		lowered := strings.ToLower(target)
		switch {
		case strings.HasPrefix(lowered, "nodeport:"), strings.HasPrefix(lowered, "hostport:"):
			best = maxInt(best, 1)
		case strings.Contains(lowered, "."):
			best = maxInt(best, 3)
		default:
			best = maxInt(best, 2)
		}
	}
	return best
}

func attributionOrder(status string) int {
	switch status {
	case "direct":
		return 0
	case "heuristic":
		return 1
	case "visibility blocked":
		return 2
	default:
		return 3
	}
}

func exposureFamilyOrder(exposureType string) int {
	switch exposureType {
	case "Ingress":
		return 0
	case "LoadBalancer":
		return 1
	case "NodePort":
		return 2
	case "HostPort":
		return 3
	case "HostNetwork":
		return 4
	default:
		return 5
	}
}

func exposureFamilyWeight(exposureType string) int {
	switch exposureType {
	case "Ingress":
		return 12
	case "LoadBalancer":
		return 10
	case "NodePort":
		return 8
	case "HostPort":
		return 5
	case "HostNetwork":
		return 4
	default:
		return 0
	}
}
