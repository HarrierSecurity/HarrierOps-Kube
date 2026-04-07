package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildRBACPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	rbacData, err := factProvider.RBACBindings(query)
	if err != nil {
		return nil, err
	}

	_, serviceAccountIssue := loadServiceAccountsSupportForRBAC(factProvider, query)
	workloadData, workloadIssue := loadWorkloadsSupportForRBAC(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForRBAC(factProvider, query)

	issues := append([]model.Issue{}, rbacData.Issues...)
	if serviceAccountIssue != nil {
		issues = append(issues, *serviceAccountIssue)
	}
	if workloadIssue != nil {
		issues = append(issues, *workloadIssue)
	}
	if exposureIssue != nil {
		issues = append(issues, *exposureIssue)
	}

	grants := enrichRBACGrants(rbacData.RoleGrants, workloadData, exposureData)
	metadata := buildMetadata("rbac", metadataContext, "")

	return structToMap(model.RbacOutput{
		Metadata:   metadata,
		RoleGrants: grants,
		Issues:     issues,
	})
}

func loadServiceAccountsSupportForRBAC(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "rbac.service-accounts",
		Message: "RBAC could not load service-account support data, so workload-linked reuse hints may be partial.",
	}
}

func loadWorkloadsSupportForRBAC(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "rbac.workloads",
		Message: "RBAC could not load workload support data, so reuse and risky-context ranking may be partial.",
	}
}

func loadExposuresSupportForRBAC(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "rbac.exposure",
		Message: "RBAC could not load exposure support data, so outside-facing workload ties may be understated.",
	}
}

func enrichRBACGrants(grants []model.RBACGrant, workloads model.WorkloadsData, exposures model.ExposureData) []model.RBACGrant {
	workloadsByServiceAccount := map[string][]model.Workload{}
	for _, workload := range workloads.WorkloadAssets {
		key := serviceAccountKey(workload.Namespace, workload.ServiceAccountName)
		workloadsByServiceAccount[key] = append(workloadsByServiceAccount[key], workload)
	}

	exposedWorkloadNames := map[string]struct{}{}
	for _, exposure := range exposures.ExposureAssets {
		for _, workloadName := range exposure.RelatedWorkloads {
			exposedWorkloadNames[workloadName] = struct{}{}
		}
	}

	enriched := make([]model.RBACGrant, 0, len(grants))
	for _, grant := range grants {
		updated := grant

		relatedWorkloads := []string{}
		riskyRelated := 0
		exposedRelated := 0

		if grant.SubjectKind == "ServiceAccount" {
			key := serviceAccountKey(derefString(grant.SubjectNamespace), grant.SubjectName)
			attachedWorkloads := workloadsByServiceAccount[key]
			for _, workload := range attachedWorkloads {
				relatedWorkloads = append(relatedWorkloads, workload.Namespace+"/"+workload.Name)
				if workload.Privileged || workload.DockerSocketMount || workload.HostNetwork || workload.HostPID || workload.HostIPC || len(workload.HostPathMounts) > 0 {
					riskyRelated++
				}
				if _, ok := exposedWorkloadNames[workload.Name]; ok {
					exposedRelated++
				}
			}
			sort.Strings(relatedWorkloads)
			updated.RelatedWorkloads = relatedWorkloads
			updated.WorkloadCount = len(relatedWorkloads)
		}

		score := rbacGrantScore(updated, riskyRelated, exposedRelated)
		updated.Priority = semanticPriority(score)
		updated.WhyCare = enrichGrantWhyCare(updated, riskyRelated, exposedRelated)
		enriched = append(enriched, updated)
	}

	sort.SliceStable(enriched, func(i, j int) bool {
		leftPriority := priorityOrder(enriched[i].Priority)
		rightPriority := priorityOrder(enriched[j].Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if enriched[i].Scope != enriched[j].Scope {
			return enriched[i].Scope == "cluster-wide"
		}
		if len(enriched[i].DangerousRights) != len(enriched[j].DangerousRights) {
			return len(enriched[i].DangerousRights) > len(enriched[j].DangerousRights)
		}
		if enriched[i].WorkloadCount != enriched[j].WorkloadCount {
			return enriched[i].WorkloadCount > enriched[j].WorkloadCount
		}
		if enriched[i].BindingName != enriched[j].BindingName {
			return enriched[i].BindingName < enriched[j].BindingName
		}
		return enriched[i].SubjectDisplay < enriched[j].SubjectDisplay
	})

	return enriched
}

func rbacGrantScore(grant model.RBACGrant, riskyRelated int, exposedRelated int) int {
	score := 0
	if grant.Scope == "cluster-wide" {
		score += 35
	}
	for _, signal := range grant.DangerousRights {
		score += providerDangerSignalScore(signal)
	}
	if grant.WorkloadCount > 0 {
		score += minInt(grant.WorkloadCount*10, 20)
	}
	score += riskyRelated * 15
	score += exposedRelated * 10
	if grant.EvidenceStatus != "direct" {
		score -= 15
	}
	return score
}

func semanticPriority(score int) string {
	switch {
	case score >= 80:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func enrichGrantWhyCare(grant model.RBACGrant, riskyRelated int, exposedRelated int) string {
	if grant.EvidenceStatus != "direct" {
		return fmt.Sprintf("%s binding is visible, but the referenced role rules were unreadable, so keep the grant visible without claiming the full capability story.", grant.Scope)
	}

	reasons := []string{}
	if len(grant.DangerousRights) > 0 {
		reasons = append(reasons, grant.DangerousRights[0])
	}
	if grant.Scope == "cluster-wide" {
		reasons = append(reasons, "cluster-wide scope")
	}
	if grant.WorkloadCount > 0 {
		workloadSummary := fmt.Sprintf("used by %d visible workload", grant.WorkloadCount)
		if grant.WorkloadCount != 1 {
			workloadSummary += "s"
		}
		reasons = append(reasons, workloadSummary)
	}
	if riskyRelated > 0 {
		reasons = append(reasons, "attached to risky workload context")
	}
	if exposedRelated > 0 {
		reasons = append(reasons, "tied to exposed workload context")
	}

	if len(reasons) == 0 {
		return fmt.Sprintf("%s grant looks narrower, but it still grounds who is bound to what access.", grant.Scope)
	}
	return fmt.Sprintf("%s grant stands out because of %s.", grant.Scope, strings.Join(reasons, ", "))
}

func providerDangerSignalScore(signal string) int {
	switch signal {
	case "admin-like wildcard access":
		return 60
	case "impersonate serviceaccounts", "impersonate users", "impersonate groups", "impersonate identities":
		return 50
	case "bind roles", "escalate roles":
		return 45
	case "change workloads", "exec into pods":
		return 35
	case "read secrets":
		return 25
	default:
		return 10
	}
}

func serviceAccountKey(namespace string, name string) string {
	return namespace + "/" + name
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func priorityOrder(priority string) int {
	switch priority {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
