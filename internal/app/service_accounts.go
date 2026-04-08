package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildServiceAccountsPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	serviceAccountData, err := factProvider.ServiceAccounts(query)
	if err != nil {
		return nil, err
	}

	workloadData, workloadIssue := loadWorkloadsSupportForServiceAccounts(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForServiceAccounts(factProvider, query)
	rbacData, rbacIssue := loadRBACSupportForServiceAccounts(factProvider, query)

	issues := append([]model.Issue{}, serviceAccountData.Issues...)
	issues = append(issues, workloadData.Issues...)
	issues = append(issues, exposureData.Issues...)
	issues = append(issues, rbacData.Issues...)
	if workloadIssue != nil {
		issues = append(issues, *workloadIssue)
	}
	if exposureIssue != nil {
		issues = append(issues, *exposureIssue)
	}
	if rbacIssue != nil {
		issues = append(issues, *rbacIssue)
	}

	metadata := buildMetadata("service-accounts", metadataContext, "")
	rows := enrichServiceAccountPaths(
		serviceAccountData.ServiceAccounts,
		workloadData,
		exposureData,
		rbacData,
	)

	return structToMap(model.ServiceAccountsOutput{
		Metadata:        metadata,
		ServiceAccounts: rows,
		Findings:        serviceAccountData.Findings,
		Issues:          issues,
	})
}

func loadWorkloadsSupportForServiceAccounts(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "service-accounts.workloads",
		Message: "Service-account triage could not load workload support data, so workload linkage and reuse breadth may be understated.",
	}
}

func loadExposuresSupportForServiceAccounts(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "service-accounts.exposure",
		Message: "Service-account triage could not load exposure support data, so exposed workload ties may be understated.",
	}
}

func loadRBACSupportForServiceAccounts(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "service-accounts.rbac",
		Message: "Service-account triage could not load RBAC support data, so concrete power summaries may be understated.",
	}
}

func enrichServiceAccountPaths(
	serviceAccounts []model.ServiceAccount,
	workloads model.WorkloadsData,
	exposures model.ExposureData,
	rbacData model.RBACData,
) []model.ServiceAccountPath {
	workloadsByServiceAccount := map[string][]model.Workload{}
	for _, workload := range workloads.WorkloadAssets {
		key := serviceAccountKey(workload.Namespace, workload.ServiceAccountName)
		workloadsByServiceAccount[key] = append(workloadsByServiceAccount[key], workload)
	}

	exposureIDsByWorkload := map[string][]string{}
	for _, exposure := range exposures.ExposureAssets {
		for _, rawWorkloadName := range exposure.RelatedWorkloads {
			workloadKey := relatedWorkloadKey(exposure.Namespace, rawWorkloadName)
			exposureIDsByWorkload[workloadKey] = append(exposureIDsByWorkload[workloadKey], exposure.ID)
		}
	}

	grantsByServiceAccount := map[string][]model.RBACGrant{}
	for _, grant := range rbacData.RoleGrants {
		if grant.SubjectKind != "ServiceAccount" {
			continue
		}
		key := serviceAccountKey(derefString(grant.SubjectNamespace), grant.SubjectName)
		grantsByServiceAccount[key] = append(grantsByServiceAccount[key], grant)
	}

	paths := make([]model.ServiceAccountPath, 0, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		key := serviceAccountKey(serviceAccount.Namespace, serviceAccount.Name)
		attachedWorkloads := workloadsByServiceAccount[key]
		grants := grantsByServiceAccount[key]

		relatedWorkloads := make([]string, 0, len(attachedWorkloads))
		exposedWorkloads := []string{}
		riskyWorkloads := []string{}
		exposedSeen := map[string]struct{}{}

		for _, workload := range attachedWorkloads {
			workloadLabel := workload.Namespace + "/" + workload.Name
			relatedWorkloads = append(relatedWorkloads, workloadLabel)

			if isRiskyWorkload(workload) {
				riskyWorkloads = append(riskyWorkloads, workloadLabel)
			}

			if len(exposureIDsByWorkload[workloadLabel]) > 0 {
				if _, ok := exposedSeen[workloadLabel]; !ok {
					exposedWorkloads = append(exposedWorkloads, workloadLabel)
					exposedSeen[workloadLabel] = struct{}{}
				}
			}
		}

		sort.Strings(relatedWorkloads)
		sort.Strings(exposedWorkloads)
		sort.Strings(riskyWorkloads)

		power := deriveServiceAccountPower(grants)
		tokenPosture := deriveServiceAccountTokenPosture(serviceAccount, attachedWorkloads)
		score := serviceAccountPathScore(power, len(attachedWorkloads), len(exposedWorkloads), len(riskyWorkloads), tokenPosture)

		paths = append(paths, model.ServiceAccountPath{
			ID:                   serviceAccount.ID,
			Name:                 serviceAccount.Name,
			Namespace:            serviceAccount.Namespace,
			BoundRoles:           serviceAccount.BoundRoles,
			RelatedWorkloads:     relatedWorkloads,
			WorkloadCount:        len(relatedWorkloads),
			ExposedWorkloads:     exposedWorkloads,
			ExposedWorkloadCount: len(exposedWorkloads),
			RiskyWorkloads:       riskyWorkloads,
			RiskyWorkloadCount:   len(riskyWorkloads),
			EvidenceStatus:       power.EvidenceStatus,
			Priority:             semanticPriority(score),
			PowerSummary:         power.Summary,
			TokenPosture:         tokenPosture.Summary,
			WhyCare:              deriveServiceAccountWhyCare(power, len(relatedWorkloads), len(exposedWorkloads), len(riskyWorkloads), tokenPosture),
		})
	}

	sort.SliceStable(paths, func(i, j int) bool {
		leftPriority := priorityOrder(paths[i].Priority)
		rightPriority := priorityOrder(paths[j].Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if paths[i].ExposedWorkloadCount != paths[j].ExposedWorkloadCount {
			return paths[i].ExposedWorkloadCount > paths[j].ExposedWorkloadCount
		}
		if paths[i].RiskyWorkloadCount != paths[j].RiskyWorkloadCount {
			return paths[i].RiskyWorkloadCount > paths[j].RiskyWorkloadCount
		}
		if paths[i].WorkloadCount != paths[j].WorkloadCount {
			return paths[i].WorkloadCount > paths[j].WorkloadCount
		}
		if paths[i].Namespace != paths[j].Namespace {
			return paths[i].Namespace < paths[j].Namespace
		}
		return paths[i].Name < paths[j].Name
	})

	return paths
}

func relatedWorkloadKey(namespace string, rawName string) string {
	if strings.Contains(rawName, "/") {
		return rawName
	}
	return namespace + "/" + rawName
}

type serviceAccountPowerAssessment struct {
	Summary         string
	EvidenceStatus  string
	Score           int
	HasVisibleGrant bool
}

type serviceAccountTokenAssessment struct {
	Summary             string
	HasVisibleTokenPath bool
}

func deriveServiceAccountPower(grants []model.RBACGrant) serviceAccountPowerAssessment {
	assessment := serviceAccountPowerAssessment{
		EvidenceStatus: "direct",
	}
	if len(grants) == 0 {
		return assessment
	}

	assessment.HasVisibleGrant = true

	bestDirectSummary := ""
	bestDirectSummaryScore := -1
	bestDirectGrantScore := 0
	bestBlockedGrantScore := 0
	bestBlockedStatus := "visibility blocked"

	for _, grant := range grants {
		grantScore := serviceAccountGrantStrength(grant)
		if grant.EvidenceStatus == "direct" {
			if grantScore > bestDirectGrantScore {
				bestDirectGrantScore = grantScore
			}
			summary, summaryScore := strongestServiceAccountSummary(grant)
			if summary == "" {
				continue
			}
			if summaryScore > bestDirectSummaryScore || (summaryScore == bestDirectSummaryScore && summary < bestDirectSummary) {
				bestDirectSummary = summary
				bestDirectSummaryScore = summaryScore
			}
			continue
		}
		if grantScore > bestBlockedGrantScore {
			bestBlockedGrantScore = grantScore
			bestBlockedStatus = grant.EvidenceStatus
		}
	}

	assessment.Summary = bestDirectSummary
	assessment.Score = bestDirectGrantScore
	if assessment.Summary != "" || assessment.Score > 0 {
		return assessment
	}

	if bestBlockedGrantScore > 0 {
		assessment.EvidenceStatus = bestBlockedStatus
		assessment.Score = bestBlockedGrantScore
	}
	return assessment
}

func strongestServiceAccountSummary(grant model.RBACGrant) (string, int) {
	bestRight := ""
	bestRightScore := 0
	for _, right := range grant.DangerousRights {
		score := providerDangerSignalScore(right)
		if score > bestRightScore || (score == bestRightScore && right < bestRight) {
			bestRight = right
			bestRightScore = score
		}
	}

	switch bestRight {
	case "admin-like wildcard access":
		return "has cluster-wide admin-like access", bestRightScore + 15
	case "impersonate serviceaccounts", "impersonate users", "impersonate groups", "impersonate identities":
		return "can impersonate identities", bestRightScore
	case "":
		if grant.Scope == "cluster-wide" {
			return "has cluster-wide access", 15
		}
		return "", 0
	}
	return "can " + bestRight, bestRightScore
}

func serviceAccountGrantStrength(grant model.RBACGrant) int {
	score := 0
	if grant.Scope == "cluster-wide" {
		score += 15
	}
	bestDangerScore := 0
	for _, right := range grant.DangerousRights {
		bestDangerScore = maxInt(bestDangerScore, providerDangerSignalScore(right))
	}
	score += bestDangerScore
	if grant.EvidenceStatus != "direct" {
		score -= 15
	}
	return score
}

func deriveServiceAccountTokenPosture(serviceAccount model.ServiceAccount, workloads []model.Workload) serviceAccountTokenAssessment {
	assessment := serviceAccountTokenAssessment{}
	parts := []string{}
	automountVisible := 0
	automountDisabled := 0
	automountUnknown := 0
	for _, workload := range workloads {
		switch {
		case workload.AutomountServiceAccountToken == nil:
			automountUnknown++
		case *workload.AutomountServiceAccountToken:
			automountVisible++
		default:
			automountDisabled++
		}
	}

	switch {
	case automountVisible > 0:
		parts = append(parts, fmt.Sprintf("token auto-mount is visible on %d attached workload", automountVisible))
		if automountVisible != 1 {
			parts[len(parts)-1] += "s"
		}
		assessment.HasVisibleTokenPath = true
	case automountDisabled > 0 && automountUnknown == 0:
		parts = append(parts, "visible workloads disable token auto-mount")
	case len(workloads) > 0:
		parts = append(parts, "attached workload token posture is inherited or only partially visible")
	case serviceAccount.AutomountServiceAccountToken != nil && *serviceAccount.AutomountServiceAccountToken:
		parts = append(parts, "service account allows token auto-mount")
	case serviceAccount.AutomountServiceAccountToken != nil:
		parts = append(parts, "service account disables token auto-mount")
	default:
		parts = append(parts, "service account token posture is inherited or not visible")
	}

	if len(serviceAccount.SecretNames) > 0 {
		parts = append(parts, "legacy token secret is visible")
		assessment.HasVisibleTokenPath = true
	}

	assessment.Summary = strings.Join(parts, "; ")
	return assessment
}

func serviceAccountPathScore(power serviceAccountPowerAssessment, workloadCount int, exposedCount int, riskyCount int, tokenPosture serviceAccountTokenAssessment) int {
	score := 0
	if power.Score > 0 {
		score += maxInt(power.Score-10, 0)
	}
	if workloadCount > 0 {
		score += 10
	}
	if workloadCount > 1 {
		score += minInt((workloadCount-1)*10, 20)
	}
	score += exposedCount * 25
	score += riskyCount * 15
	if tokenPosture.HasVisibleTokenPath {
		score += 10
	}
	if power.EvidenceStatus != "direct" {
		score -= 15
	}
	return score
}

func deriveServiceAccountWhyCare(power serviceAccountPowerAssessment, workloadCount int, exposedCount int, riskyCount int, tokenPosture serviceAccountTokenAssessment) string {
	if power.EvidenceStatus != "direct" {
		return "Current scope shows the identity path, but unreadable grant detail keeps the stronger power story unconfirmed."
	}

	reasons := []string{}
	if power.Summary != "" {
		reasons = append(reasons, power.Summary)
	}
	if exposedCount > 0 {
		reasons = append(reasons, countSummary(exposedCount, "fronts %d exposed workload", "fronts %d exposed workloads"))
	}
	if riskyCount > 0 {
		reasons = append(reasons, countSummary(riskyCount, "touches %d risky workload context", "touches %d risky workload contexts"))
	}
	if workloadCount > 1 {
		reasons = append(reasons, fmt.Sprintf("is reused by %d visible workloads", workloadCount))
	} else if workloadCount == 1 {
		reasons = append(reasons, "is used by 1 visible workload")
	}
	if tokenPosture.HasVisibleTokenPath {
		reasons = append(reasons, "has a visible token path")
	}

	if len(reasons) > 0 {
		return fmt.Sprintf("Identity path stands out because it %s.", strings.Join(reasons, ", "))
	}
	if power.HasVisibleGrant {
		return "Identity path is visible, but the attached grant signal stays narrower."
	}
	if workloadCount > 0 {
		return "Identity path is visible through attached workloads, but stronger grant or exposure signal is not visible."
	}
	return "Service account is visible, but current scope does not confirm attached workload paths."
}

func countSummary(count int, singular string, plural string) string {
	if count == 1 {
		return fmt.Sprintf(singular, count)
	}
	return fmt.Sprintf(plural, count)
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}
