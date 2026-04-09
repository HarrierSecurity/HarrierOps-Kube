package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildSecretsPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	serviceAccountData, err := factProvider.ServiceAccounts(query)
	if err != nil {
		return nil, err
	}

	workloadData, workloadIssue := loadWorkloadsSupportForSecrets(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForSecrets(factProvider, query)
	rbacData, rbacIssue := loadRBACSupportForSecrets(factProvider, query)

	rows := enrichSecretPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	if rows == nil {
		rows = []model.SecretPath{}
	}

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

	return structToMap(model.SecretsOutput{
		Metadata:    buildMetadata("secrets", metadataContext, ""),
		SecretPaths: rows,
		Issues:      issues,
	})
}

func loadWorkloadsSupportForSecrets(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "secrets.workloads",
		Message: "Secret-path triage could not load workload support data, so execution linkage and trust significance may be understated.",
	}
}

func loadExposuresSupportForSecrets(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "secrets.exposure",
		Message: "Secret-path triage could not load exposure support data, so outside-facing workload ties may be understated.",
	}
}

func loadRBACSupportForSecrets(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "secrets.rbac",
		Message: "Secret-path triage could not load RBAC support data, so attached identity significance may be understated.",
	}
}

func enrichSecretPaths(
	serviceAccounts []model.ServiceAccount,
	workloads model.WorkloadsData,
	exposures model.ExposureData,
	rbacData model.RBACData,
) []model.SecretPath {
	workloadsByServiceAccount := map[string][]model.Workload{}
	workloadsByKey := map[string]model.Workload{}
	workloadsByNamespace := map[string][]model.Workload{}
	for _, workload := range workloads.WorkloadAssets {
		workloadsByServiceAccount[serviceAccountKey(workload.Namespace, workload.ServiceAccountName)] = append(
			workloadsByServiceAccount[serviceAccountKey(workload.Namespace, workload.ServiceAccountName)],
			workload,
		)
		workloadsByKey[relatedWorkloadKey(workload.Namespace, workload.Name)] = workload
		workloadsByNamespace[workload.Namespace] = append(workloadsByNamespace[workload.Namespace], workload)
	}

	publicExposureByWorkload := map[string]bool{}
	for _, exposure := range exposures.ExposureAssets {
		if !exposure.Public {
			continue
		}
		matched := matchExposureWorkloads(exposure, workloadsByKey, workloadsByNamespace)
		for _, workloadLabel := range matched.Labels {
			publicExposureByWorkload[workloadLabel] = true
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

	rows := []model.SecretPath{}
	for _, serviceAccount := range serviceAccounts {
		key := serviceAccountKey(serviceAccount.Namespace, serviceAccount.Name)
		attachedWorkloads := workloadsByServiceAccount[key]
		power := deriveServiceAccountPower(grantsByServiceAccount[key])

		for _, secretName := range serviceAccount.SecretNames {
			rows = append(rows, buildSecretNamePath(serviceAccount, secretName, attachedWorkloads, publicExposureByWorkload, power))
		}
		for _, secretName := range serviceAccount.ImagePullSecrets {
			rows = append(rows, buildImagePullSecretPath(serviceAccount, secretName, attachedWorkloads, publicExposureByWorkload, power))
		}
		if len(serviceAccount.SecretNames) == 0 && visibleAutomountTokenPath(serviceAccount, attachedWorkloads) {
			rows = append(rows, buildProjectedTokenPath(serviceAccount, attachedWorkloads, publicExposureByWorkload, power))
		}
	}

	for _, workload := range workloads.WorkloadAssets {
		if !looksExternalSecretDependency(workload) {
			continue
		}
		rows = append(rows, buildExternalSecretDependencyPath(workload, publicExposureByWorkload[workload.Namespace+"/"+workload.Name]))
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if priorityOrder(rows[i].Priority) != priorityOrder(rows[j].Priority) {
			return priorityOrder(rows[i].Priority) < priorityOrder(rows[j].Priority)
		}
		if secretStoryRank(rows[i].SecretStory) != secretStoryRank(rows[j].SecretStory) {
			return secretStoryRank(rows[i].SecretStory) > secretStoryRank(rows[j].SecretStory)
		}
		if len(rows[i].RelatedWorkloads) != len(rows[j].RelatedWorkloads) {
			return len(rows[i].RelatedWorkloads) > len(rows[j].RelatedWorkloads)
		}
		if secretDirectUseRank(rows[i].DirectUseConfidence) != secretDirectUseRank(rows[j].DirectUseConfidence) {
			return secretDirectUseRank(rows[i].DirectUseConfidence) > secretDirectUseRank(rows[j].DirectUseConfidence)
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		return rows[i].SafeLabel < rows[j].SafeLabel
	})

	return rows
}

func buildSecretNamePath(
	serviceAccount model.ServiceAccount,
	secretName string,
	attachedWorkloads []model.Workload,
	publicExposureByWorkload map[string]bool,
	power serviceAccountPowerAssessment,
) model.SecretPath {
	workloadLabels, exposed, risky, central := summarizeSecretWorkloadLinkage(attachedWorkloads, publicExposureByWorkload)
	likelyType := "unknown local secret"
	targetFamily := "unknown"
	confidence := "direct"
	directUseConfidence := "possible"
	trustPath := fmt.Sprintf("ServiceAccount %s/%s stores %s locally.", serviceAccount.Namespace, serviceAccount.Name, secretName)
	if looksServiceAccountTokenSecret(secretName) {
		likelyType = "service-account token"
		targetFamily = "kubernetes api"
		directUseConfidence = "direct"
		trustPath = fmt.Sprintf("ServiceAccount %s/%s stores a legacy token secret locally.", serviceAccount.Namespace, serviceAccount.Name)
	}

	score := 45 + secretLinkageScore(exposed, risky, central, power)
	return model.SecretPath{
		ID:                  "secret-path:" + serviceAccount.Namespace + ":" + serviceAccount.Name + ":secret:" + secretName,
		SecretStory:         "stores-secret",
		SafeLabel:           secretName,
		SourceSurface:       "service-account secret",
		Namespace:           serviceAccount.Namespace,
		Subject:             "ServiceAccount " + serviceAccount.Namespace + "/" + serviceAccount.Name,
		RelatedWorkloads:    workloadLabels,
		LikelySecretType:    likelyType,
		LikelyTargetFamily:  targetFamily,
		Confidence:          confidence,
		DirectUseConfidence: directUseConfidence,
		TrustPath:           trustPath,
		OperatorSignal:      secretOperatorSignal(score),
		Priority:            semanticPriority(score),
		WhyCare:             deriveSecretWhyCare("stores-secret", likelyType, targetFamily, workloadLabels, exposed, risky, central, power),
		NextReview:          secretNextReview("stores-secret", exposed, risky),
	}
}

func buildImagePullSecretPath(
	serviceAccount model.ServiceAccount,
	secretName string,
	attachedWorkloads []model.Workload,
	publicExposureByWorkload map[string]bool,
	power serviceAccountPowerAssessment,
) model.SecretPath {
	workloadLabels, exposed, risky, central := summarizeSecretWorkloadLinkage(attachedWorkloads, publicExposureByWorkload)
	score := 30 + secretLinkageScore(exposed, risky, central, power)
	return model.SecretPath{
		ID:                  "secret-path:" + serviceAccount.Namespace + ":" + serviceAccount.Name + ":image-pull:" + secretName,
		SecretStory:         "stores-secret",
		SafeLabel:           secretName,
		SourceSurface:       "image pull secret",
		Namespace:           serviceAccount.Namespace,
		Subject:             "ServiceAccount " + serviceAccount.Namespace + "/" + serviceAccount.Name,
		RelatedWorkloads:    workloadLabels,
		LikelySecretType:    "registry credential",
		LikelyTargetFamily:  "container registry",
		Confidence:          "direct",
		DirectUseConfidence: "likely",
		TrustPath:           fmt.Sprintf("ServiceAccount %s/%s references a local image pull secret.", serviceAccount.Namespace, serviceAccount.Name),
		OperatorSignal:      secretOperatorSignal(score),
		Priority:            semanticPriority(score),
		WhyCare:             deriveSecretWhyCare("stores-secret", "registry credential", "container registry", workloadLabels, exposed, risky, central, power),
		NextReview:          secretNextReview("stores-secret", exposed, risky),
	}
}

func buildProjectedTokenPath(
	serviceAccount model.ServiceAccount,
	attachedWorkloads []model.Workload,
	publicExposureByWorkload map[string]bool,
	power serviceAccountPowerAssessment,
) model.SecretPath {
	workloadLabels, exposed, risky, central := summarizeSecretWorkloadLinkage(attachedWorkloads, publicExposureByWorkload)
	score := 35 + secretLinkageScore(exposed, risky, central, power)
	return model.SecretPath{
		ID:                  "secret-path:" + serviceAccount.Namespace + ":" + serviceAccount.Name + ":projected-token",
		SecretStory:         "stores-secret",
		SafeLabel:           "projected service-account token path",
		SourceSurface:       "workload token mount",
		Namespace:           serviceAccount.Namespace,
		Subject:             "ServiceAccount " + serviceAccount.Namespace + "/" + serviceAccount.Name,
		RelatedWorkloads:    workloadLabels,
		LikelySecretType:    "projected service-account token",
		LikelyTargetFamily:  "kubernetes api",
		Confidence:          "direct",
		DirectUseConfidence: "likely",
		TrustPath:           fmt.Sprintf("Workloads running as ServiceAccount %s/%s visibly auto-mount a service-account token path.", serviceAccount.Namespace, serviceAccount.Name),
		OperatorSignal:      secretOperatorSignal(score),
		Priority:            semanticPriority(score),
		WhyCare:             deriveSecretWhyCare("stores-secret", "projected service-account token", "kubernetes api", workloadLabels, exposed, risky, central, power),
		NextReview:          secretNextReview("stores-secret", exposed, risky),
	}
}

func buildExternalSecretDependencyPath(workload model.Workload, publicExposure bool) model.SecretPath {
	score := 20
	if publicExposure {
		score += 20
	}
	if isRiskyWorkload(workload) {
		score += 10
	}
	if workloadLooksOperationallyCentral(workload) {
		score += 10
	}
	workloadLabel := workload.Namespace + "/" + workload.Name
	return model.SecretPath{
		ID:                  "secret-path:" + workload.Namespace + ":" + workload.Name + ":external-dependency",
		SecretStory:         "uses-external-secret",
		SafeLabel:           workload.Name,
		SourceSurface:       "workload dependency",
		Namespace:           workload.Namespace,
		Subject:             "Workload " + workloadLabel,
		RelatedWorkloads:    []string{workloadLabel},
		LikelySecretType:    "external secret dependency",
		LikelyTargetFamily:  "external secret store",
		Confidence:          "likely",
		DirectUseConfidence: "possible",
		TrustPath:           fmt.Sprintf("Workload %s looks like it depends on an external secret system rather than only local secret storage.", workloadLabel),
		OperatorSignal:      secretOperatorSignal(score),
		Priority:            semanticPriority(score),
		WhyCare:             deriveExternalSecretWhyCare(workload, publicExposure),
		NextReview:          "workloads",
	}
}

func summarizeSecretWorkloadLinkage(attachedWorkloads []model.Workload, publicExposureByWorkload map[string]bool) ([]string, int, int, int) {
	workloadLabels := make([]string, 0, len(attachedWorkloads))
	exposed := 0
	risky := 0
	central := 0
	for _, workload := range attachedWorkloads {
		workloadLabel := workload.Namespace + "/" + workload.Name
		workloadLabels = append(workloadLabels, workloadLabel)
		if publicExposureByWorkload[workloadLabel] {
			exposed++
		}
		if isRiskyWorkload(workload) {
			risky++
		}
		if workloadLooksOperationallyCentral(workload) {
			central++
		}
	}
	sort.Strings(workloadLabels)
	return workloadLabels, exposed, risky, central
}

func secretLinkageScore(exposed int, risky int, central int, power serviceAccountPowerAssessment) int {
	score := 0
	score += exposed * 20
	score += risky * 15
	score += central * 10
	if power.Score > 0 {
		score += minInt(power.Score/3, 25)
	}
	return score
}

func deriveSecretWhyCare(
	secretStory string,
	likelyType string,
	targetFamily string,
	workloadLabels []string,
	exposed int,
	risky int,
	central int,
	power serviceAccountPowerAssessment,
) string {
	reasons := []string{}
	if likelyType != "" && likelyType != "unknown local secret" {
		reasons = append(reasons, likelyType)
	}
	if targetFamily != "" && targetFamily != "unknown" {
		reasons = append(reasons, "likely unlocks "+targetFamily)
	}
	if exposed > 0 {
		reasons = append(reasons, countSummary(exposed, "touches %d exposed workload path", "touches %d exposed workload paths"))
	}
	if risky > 0 {
		reasons = append(reasons, countSummary(risky, "touches %d risky workload context", "touches %d risky workload contexts"))
	}
	if central > 0 {
		reasons = append(reasons, countSummary(central, "sits near %d operationally central workload", "sits near %d operationally central workloads"))
	}
	if power.Summary != "" {
		reasons = append(reasons, power.Summary)
	}
	if len(workloadLabels) == 1 {
		reasons = append(reasons, "is tied to "+workloadLabels[0])
	} else if len(workloadLabels) > 1 {
		reasons = append(reasons, fmt.Sprintf("is reused by %d visible workloads", len(workloadLabels)))
	}
	if len(reasons) == 0 {
		if secretStory == "stores-secret" {
			return "Secret path stays visible because local secret custody is visible even though stronger workload or identity consequence is not."
		}
		return "Secret dependency stays visible because it may bridge trust even though the downstream target is still fuzzy."
	}
	return fmt.Sprintf("Secret path rises because it shows %s.", strings.Join(reasons, ", "))
}

func deriveExternalSecretWhyCare(workload model.Workload, publicExposure bool) string {
	reasons := []string{}
	if publicExposure {
		reasons = append(reasons, "sits behind a public-looking workload path")
	}
	if isRiskyWorkload(workload) {
		reasons = append(reasons, "touches risky execution context")
	}
	if workloadLooksOperationallyCentral(workload) {
		reasons = append(reasons, "looks operationally central")
	}
	if len(reasons) == 0 {
		return "Dependency stays visible because it may point to an external trust bridge rather than only local secret storage."
	}
	return fmt.Sprintf("Secret dependency rises because it %s.", strings.Join(reasons, ", "))
}

func secretNextReview(secretStory string, exposed int, risky int) string {
	if secretStory == "uses-external-secret" {
		return "workloads"
	}
	if exposed > 0 || risky > 0 {
		return "workloads"
	}
	return "service-accounts"
}

func secretOperatorSignal(score int) string {
	switch {
	case score >= 75:
		return "review-now"
	case score >= 40:
		return "review-soon"
	default:
		return "bookmark"
	}
}

func secretStoryRank(secretStory string) int {
	switch secretStory {
	case "shows-cleartext":
		return 4
	case "hides-secret-weakly":
		return 3
	case "stores-secret":
		return 2
	case "uses-external-secret":
		return 1
	default:
		return 0
	}
}

func secretDirectUseRank(confidence string) int {
	switch confidence {
	case "direct":
		return 4
	case "likely":
		return 3
	case "possible":
		return 2
	default:
		return 1
	}
}

func looksServiceAccountTokenSecret(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "token")
}

func visibleAutomountTokenPath(serviceAccount model.ServiceAccount, workloads []model.Workload) bool {
	for _, workload := range workloads {
		if workload.AutomountServiceAccountToken != nil && *workload.AutomountServiceAccountToken {
			return true
		}
	}
	return serviceAccount.AutomountServiceAccountToken != nil && *serviceAccount.AutomountServiceAccountToken
}

func looksExternalSecretDependency(workload model.Workload) bool {
	candidates := []string{strings.ToLower(workload.Name)}
	for _, image := range workload.Images {
		candidates = append(candidates, strings.ToLower(image))
	}
	for _, candidate := range candidates {
		for _, marker := range []string{"external-secrets", "secret-store", "secrets-store", "vault-agent", "secret-store-csi"} {
			if strings.Contains(candidate, marker) {
				return true
			}
		}
	}
	return false
}
