package chains

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
)

type WorkloadIdentityPivotInputs struct {
	StartingFoothold string
	Workloads        []model.WorkloadPath
	ServiceAccounts  []model.ServiceAccountPath
	Permissions      []model.PermissionPath
	Secrets          []model.SecretPath
	Issues           []model.Issue
}

func BuildWorkloadIdentityPivotOutput(metadata contracts.Metadata, inputs WorkloadIdentityPivotInputs) (model.ChainsOutput, error) {
	spec, ok := FamilySpecFor("workload-identity-pivot")
	if !ok {
		return model.ChainsOutput{}, fmt.Errorf("unknown chain family %q", "workload-identity-pivot")
	}

	rows := buildWorkloadIdentityPivotRows(inputs)
	sort.SliceStable(rows, func(i, j int) bool {
		leftPriority := chainPriorityOrder(rows[i].Priority)
		rightPriority := chainPriorityOrder(rows[j].Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if visibilityTierRank(rows[i].VisibilityTier) != visibilityTierRank(rows[j].VisibilityTier) {
			return visibilityTierRank(rows[i].VisibilityTier) < visibilityTierRank(rows[j].VisibilityTier)
		}
		if chainPathTypeRank(rows[i].PathType) != chainPathTypeRank(rows[j].PathType) {
			return chainPathTypeRank(rows[i].PathType) < chainPathTypeRank(rows[j].PathType)
		}
		return rows[i].SourceAsset < rows[j].SourceAsset
	})

	summary := "No bounded workload-identity pivot rows were confirmed from current scope."
	commandState := "ok"
	if len(rows) > 0 {
		summary = fmt.Sprintf("%d workload-linked identity path", len(rows))
		if len(rows) == 1 {
			summary += " is"
		} else {
			summary += "s are"
		}
		summary += " ready for first review."
	}

	return model.ChainsOutput{
		Metadata:           metadata,
		GroupedCommandName: GroupedCommandName,
		Family:             "workload-identity-pivot",
		InputMode:          "live",
		CommandState:       commandState,
		Summary:            summary,
		ClaimBoundary:      spec.AllowedClaim,
		BackingCommands:    []string{"workloads", "service-accounts", "permissions", "secrets"},
		Paths:              rows,
		Issues:             inputs.Issues,
	}, nil
}

func buildWorkloadIdentityPivotRows(inputs WorkloadIdentityPivotInputs) []model.ChainPathRecord {
	workloadByLabel := map[string]model.WorkloadPath{}
	workloadByNamespace := map[string][]model.WorkloadPath{}
	for _, workload := range inputs.Workloads {
		label := workload.Namespace + "/" + workload.Name
		workloadByLabel[label] = workload
		workloadByNamespace[workload.Namespace] = append(workloadByNamespace[workload.Namespace], workload)
	}

	serviceAccountByKey := map[string]model.ServiceAccountPath{}
	for _, serviceAccount := range inputs.ServiceAccounts {
		serviceAccountByKey[serviceAccount.Namespace+"/"+serviceAccount.Name] = serviceAccount
	}

	rows := []model.ChainPathRecord{}
	rows = append(rows, buildExecIntoPodsRows(inputs, workloadByNamespace, serviceAccountByKey)...)
	rows = append(rows, buildReadSecretsRows(inputs, workloadByLabel, serviceAccountByKey)...)
	rows = append(rows, buildSwitchServiceAccountRows(inputs, workloadByNamespace, serviceAccountByKey)...)
	rows = append(rows, buildPatchSpecificSurfaceRows(inputs, workloadByNamespace, serviceAccountByKey)...)
	rows = append(rows, buildTokenPathVisibleRows(inputs, workloadByLabel)...)
	return rows
}

func buildExecIntoPodsRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, permission := range inputs.Permissions {
		if permission.ActionSummary != "can exec into pods" {
			continue
		}

		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		workload, ok := strongestWorkloadForScope(namespace, workloadByNamespace, serviceAccountByKey)
		if !ok {
			continue
		}

		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			SubversionPointVisible:  true,
			AttachedIdentityVisible: workload.ServiceAccountName != "",
			StrongerControlVisible:  serviceAccount.PowerSummary != "",
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowExecIntoPodsInNamespace,
		})
		if !decision.AllowedDefault {
			continue
		}

		controlSummary := "attached service account changes the next move"
		if serviceAccount.PowerSummary != "" {
			controlSummary = "attached service account " + serviceAccount.PowerSummary
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:exec:" + workload.Namespace + ":" + workload.Name,
			Priority:                workload.Priority,
			InternalProofState:      "path-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control visible",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "exec into pods in namespace " + workload.Namespace,
			LikelyKubernetesControl: controlSummary,
			Urgency:                 "now",
			WhyStopHere:             "current foothold can reach an already running workload with stronger identity",
			ConfidenceBoundary:      "Current scope confirms the current foothold can exec into pods in namespace " + workload.Namespace + ".",
			NextReview:              "workloads",
			Summary:                 visibility.OperatorWording,
			MissingConfirmation:     ExecIntoPodsMissingConfirmation(workload.Namespace),
			EvidenceCommands:        []string{"permissions", "workloads", "service-accounts"},
			RelatedIDs:              []string{workload.ID, serviceAccount.ID, permission.ID},
		})
	}
	return rows
}

func buildReadSecretsRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByLabel map[string]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, permission := range inputs.Permissions {
		if permission.ActionSummary != "can read secrets" {
			continue
		}

		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		secretPath, workload, serviceAccount, ok := strongestSecretPathForScope(namespace, inputs.Secrets, workloadByLabel, serviceAccountByKey)
		if !ok {
			continue
		}

		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			SubversionPointVisible:  true,
			AttachedIdentityVisible: workload.ServiceAccountName != "",
			StrongerControlVisible:  serviceAccount.PowerSummary != "",
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowReadSecretsInNamespace,
		})
		if !decision.AllowedDefault {
			continue
		}

		controlSummary := secretPath.LikelyTargetFamily
		if serviceAccount.PowerSummary != "" {
			controlSummary = "attached service account " + serviceAccount.PowerSummary
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:secret-read:" + secretPath.Namespace + ":" + secretPath.SafeLabel,
			Priority:                secretPath.Priority,
			InternalProofState:      "path-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control visible",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "read secrets in namespace " + secretPath.Namespace,
			LikelyKubernetesControl: controlSummary,
			Urgency:                 "now",
			WhyStopHere:             "current foothold can read secret-backed workload trust material in this namespace",
			ConfidenceBoundary:      "Current scope confirms the current foothold can read secrets in namespace " + secretPath.Namespace + ".",
			NextReview:              secretPath.NextReview,
			Summary:                 visibility.OperatorWording,
			MissingConfirmation:     ReadSecretsMissingConfirmation(secretPath.Namespace),
			EvidenceCommands:        []string{"permissions", "secrets", "workloads", "service-accounts"},
			RelatedIDs:              []string{permission.ID, secretPath.ID, workload.ID, serviceAccount.ID},
		})
	}
	return rows
}

func buildTokenPathVisibleRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByLabel map[string]model.WorkloadPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, serviceAccount := range inputs.ServiceAccounts {
		if !strings.Contains(serviceAccount.TokenPosture, "visible token path") && !strings.Contains(serviceAccount.TokenPosture, "legacy token secret is visible") {
			continue
		}
		if len(serviceAccount.RelatedWorkloads) == 0 || serviceAccount.PowerSummary == "" {
			continue
		}

		workload, ok := workloadByLabel[serviceAccount.RelatedWorkloads[0]]
		if !ok {
			continue
		}

		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			AttachedIdentityVisible: true,
			StrongerControlVisible:  true,
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowTokenPathVisible,
		})
		if !decision.AllowedDefault {
			continue
		}

		relatedIDs := []string{serviceAccount.ID}
		if workload.ID != "" {
			relatedIDs = append(relatedIDs, workload.ID)
		}
		if secretID, ok := strongestTokenSecretIDForWorkload(workload.Namespace+"/"+workload.Name, inputs.Secrets); ok {
			relatedIDs = append(relatedIDs, secretID)
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:token-path:" + workload.Namespace + ":" + workload.Name,
			Priority:                serviceAccount.Priority,
			InternalProofState:      "target-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control not confirmed",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "review visible workload-linked token path",
			LikelyKubernetesControl: "attached service account " + serviceAccount.PowerSummary,
			Urgency:                 "soon",
			WhyStopHere:             "current scope can see a workload-linked token path on stronger identity",
			ConfidenceBoundary:      "Current scope confirms a workload-linked token path is visible, but runtime inspection is not yet proven.",
			NextReview:              "workloads",
			Summary:                 visibility.OperatorWording,
			MissingConfirmation:     TokenPathVisibleMissingConfirmation(),
			EvidenceCommands:        []string{"service-accounts", "secrets", "workloads", "privesc"},
			RelatedIDs:              relatedIDs,
		})
	}
	return rows
}

func buildPatchSpecificSurfaceRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	bestPatchPermissionByNamespace := map[string]model.PermissionPath{}
	for _, permission := range inputs.Permissions {
		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		if !permissionSupportsExactWorkloadPatchSurface(permission) {
			continue
		}

		best, seen := bestPatchPermissionByNamespace[namespace]
		if !seen || workloadChangePermissionScore(permission) > workloadChangePermissionScore(best) {
			bestPatchPermissionByNamespace[namespace] = permission
		}
	}

	namespaces := sortedStringKeys(bestPatchPermissionByNamespace)
	rows := []model.ChainPathRecord{}
	for _, namespace := range namespaces {
		permission := bestPatchPermissionByNamespace[namespace]
		for _, surface := range exactPatchSurfaceCandidates() {
			workload, serviceAccount, ok := strongestWorkloadForPatchSurface(namespace, surface, workloadByNamespace, serviceAccountByKey)
			if !ok {
				continue
			}

			visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
				WorkloadVisible:         true,
				SubversionPointVisible:  true,
				AttachedIdentityVisible: workload.ServiceAccountName != "",
				StrongerControlVisible:  serviceAccount.PowerSummary != "",
				VisibleChangeSurfaces:   true,
				ExactBlockerKnown:       true,
				NextReviewSet:           true,
			})
			if !ok {
				continue
			}

			confidenceBoundary, boundaryOK := FormatWorkloadPatchConfidenceBoundary(workloadPatchRelevantFields(workload))
			decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowPatchSpecificSurface,
				ExactActionProven:           true,
				VisibleSurface:              surface,
				VisibilityTier:              visibility.Tier,
				ConfidenceBoundaryAvailable: boundaryOK,
			})
			if !decision.AllowedDefault || visibility.SuppressDefault {
				continue
			}

			rows = append(rows, model.ChainPathRecord{
				ChainID:                 "workload-identity-pivot:patch-" + exactPatchSurfaceChainIDPart(surface) + ":" + namespace + ":" + workload.Name,
				Priority:                workload.Priority,
				InternalProofState:      "path-confirmed",
				VisibilityTier:          visibility.Tier,
				PathType:                "direct control visible",
				StartingFoothold:        inputs.StartingFoothold,
				SourceAsset:             workload.Namespace + "/" + workload.Name,
				SourceNamespace:         workload.Namespace,
				SubversionPoint:         exactPatchSurfaceSubversionPoint(permission.ActionVerb, workload.Namespace+"/"+workload.Name, surface),
				LikelyKubernetesControl: "attached service account " + serviceAccount.PowerSummary,
				Urgency:                 "now",
				WhyStopHere:             WorkloadPatchWhyStopHere(),
				ConfidenceBoundary:      confidenceBoundary,
				NextReview:              "workloads",
				Summary:                 visibility.OperatorWording,
				MissingConfirmation:     PatchSurfaceMissingConfirmation(surface),
				EvidenceCommands:        []string{"permissions", "workloads", "service-accounts"},
				RelatedIDs:              []string{permission.ID, workload.ID, serviceAccount.ID},
			})
		}
	}

	return rows
}

func buildSwitchServiceAccountRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	bestPermissionByNamespace := map[string]model.PermissionPath{}
	for _, permission := range inputs.Permissions {
		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		if !permissionSupportsServiceAccountRepointing(permission) {
			continue
		}

		best, seen := bestPermissionByNamespace[namespace]
		if !seen || workloadChangePermissionScore(permission) > workloadChangePermissionScore(best) {
			bestPermissionByNamespace[namespace] = permission
		}
	}

	rows := []model.ChainPathRecord{}
	for namespace, permission := range bestPermissionByNamespace {
		option, ok := strongestWorkloadForServiceAccountSwitch(permission, namespace, workloadByNamespace, serviceAccountByKey)
		if !ok {
			continue
		}

		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			SubversionPointVisible:  true,
			AttachedIdentityVisible: option.Workload.ServiceAccountName != "",
			StrongerControlVisible:  len(option.StrongerCandidates) > 0,
			VisibleChangeSurfaces:   true,
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		if option.ExactCandidate != nil {
			target := *option.ExactCandidate
			confidenceBoundary, boundaryOK := FormatExactServiceAccountSwitchConfidenceBoundary(
				namespace,
				namespacedServiceAccountLabel(target.Namespace, target.Name),
			)
			decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowSwitchServiceAccount,
				ExactActionProven:           true,
				VisibleSurface:              "service account",
				VisibilityTier:              visibility.Tier,
				ConfidenceBoundaryAvailable: boundaryOK,
				ExactTargetNamed:            true,
			})
			if decision.AllowedDefault && !visibility.SuppressDefault {
				relatedIDs := []string{permission.ID, option.Workload.ID}
				if option.CurrentServiceAccount.ID != "" {
					relatedIDs = append(relatedIDs, option.CurrentServiceAccount.ID)
				}
				relatedIDs = append(relatedIDs, target.ID)

				rows = append(rows, buildServiceAccountSwitchRecord(serviceAccountSwitchRecordInputs{
					ChainID:                 "workload-identity-pivot:switch-service-account:" + namespace + ":" + option.Workload.Name + ":" + target.Name,
					Priority:                option.Workload.Priority,
					InternalProofState:      "path-confirmed",
					VisibilityTier:          visibility.Tier,
					PathType:                "direct control visible",
					StartingFoothold:        inputs.StartingFoothold,
					SourceAsset:             option.Workload.Namespace + "/" + option.Workload.Name,
					SourceNamespace:         option.Workload.Namespace,
					SubversionPoint:         "switch workload " + option.Workload.Namespace + "/" + option.Workload.Name + " to service account " + target.Namespace + "/" + target.Name,
					LikelyKubernetesControl: "service account " + target.Namespace + "/" + target.Name + " " + target.PowerSummary,
					Urgency:                 "now",
					WhyStopHere:             workloadServiceAccountSwitchWhyStopHere,
					ConfidenceBoundary:      confidenceBoundary,
					NextReview:              "service-accounts",
					Summary:                 visibility.OperatorWording,
					MissingConfirmation:     ExactServiceAccountSwitchMissingConfirmation(namespace, namespacedServiceAccountLabel(target.Namespace, target.Name)),
					EvidenceCommands:        []string{"permissions", "workloads", "service-accounts"},
					RelatedIDs:              relatedIDs,
				}))
				continue
			}
		}

		confidenceBoundary, boundaryOK := FormatBoundedServiceAccountSwitchConfidenceBoundary(
			namespace,
			namespacedServiceAccountLabel(namespace, option.Workload.ServiceAccountName),
		)
		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind:                        WorkloadIdentityRowSwitchServiceAccount,
			ExactActionProven:           true,
			VisibleSurface:              "service account",
			VisibilityTier:              visibility.Tier,
			ConfidenceBoundaryAvailable: boundaryOK,
			WeakerFallbackAvailable:     len(option.StrongerCandidates) > 0,
		})
		if !decision.AllowedDefault || visibility.SuppressDefault {
			continue
		}

		relatedIDs := []string{permission.ID, option.Workload.ID}
		if option.CurrentServiceAccount.ID != "" {
			relatedIDs = append(relatedIDs, option.CurrentServiceAccount.ID)
		}
		for _, candidate := range option.StrongerCandidates {
			relatedIDs = append(relatedIDs, candidate.ID)
		}

		rows = append(rows, buildServiceAccountSwitchRecord(serviceAccountSwitchRecordInputs{
			ChainID:                 "workload-identity-pivot:review-switch-service-account:" + namespace + ":" + option.Workload.Name,
			Priority:                option.Workload.Priority,
			InternalProofState:      "visible",
			VisibilityTier:          visibility.Tier,
			PathType:                "workload pivot",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             option.Workload.Namespace + "/" + option.Workload.Name,
			SourceNamespace:         option.Workload.Namespace,
			SubversionPoint:         "review stronger service-account repointing on workload " + option.Workload.Namespace + "/" + option.Workload.Name,
			LikelyKubernetesControl: boundedServiceAccountControlSummary(option.StrongerCandidates),
			Urgency:                 "soon",
			WhyStopHere:             workloadServiceAccountFallbackWhyStopHere,
			ConfidenceBoundary:      confidenceBoundary,
			NextReview:              "service-accounts",
			Summary:                 visibility.OperatorWording,
			MissingConfirmation:     BoundedServiceAccountSwitchMissingConfirmation(),
			EvidenceCommands:        []string{"permissions", "workloads", "service-accounts"},
			RelatedIDs:              relatedIDs,
		}))
	}

	return rows
}

func strongestWorkloadForScope(
	namespace string,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (model.WorkloadPath, bool) {
	if namespace != "" {
		return strongestWorkload(workloadByNamespace[namespace], serviceAccountByKey)
	}

	all := []model.WorkloadPath{}
	for _, workloads := range workloadByNamespace {
		all = append(all, workloads...)
	}
	return strongestWorkload(all, serviceAccountByKey)
}

func strongestWorkload(workloads []model.WorkloadPath, serviceAccountByKey map[string]model.ServiceAccountPath) (model.WorkloadPath, bool) {
	bestIndex := -1
	bestScore := -1
	for index, workload := range workloads {
		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		if serviceAccount.PowerSummary == "" {
			continue
		}

		score := triageScore(workload.Priority)
		if workload.PublicExposure {
			score += 10
		}
		if len(workload.RiskSignals) > 0 {
			score += 5
		}
		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}
	if bestIndex == -1 {
		return model.WorkloadPath{}, false
	}
	return workloads[bestIndex], true
}

func strongestSecretPathForScope(
	namespace string,
	secrets []model.SecretPath,
	workloadByLabel map[string]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (model.SecretPath, model.WorkloadPath, model.ServiceAccountPath, bool) {
	bestIndex := -1
	bestScore := -1
	var bestWorkload model.WorkloadPath
	var bestServiceAccount model.ServiceAccountPath

	for index, secretPath := range secrets {
		if namespace != "" && secretPath.Namespace != namespace {
			continue
		}
		if len(secretPath.RelatedWorkloads) == 0 {
			continue
		}
		workload, ok := workloadByLabel[secretPath.RelatedWorkloads[0]]
		if !ok {
			continue
		}
		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]

		score := triageScore(secretPath.Priority) + triageScore(workload.Priority)
		if serviceAccount.PowerSummary != "" {
			score += 10
		}
		if score > bestScore {
			bestScore = score
			bestIndex = index
			bestWorkload = workload
			bestServiceAccount = serviceAccount
		}
	}
	if bestIndex == -1 {
		return model.SecretPath{}, model.WorkloadPath{}, model.ServiceAccountPath{}, false
	}
	return secrets[bestIndex], bestWorkload, bestServiceAccount, true
}

func strongestTokenSecretIDForWorkload(workloadLabel string, secrets []model.SecretPath) (string, bool) {
	for _, secretPath := range secrets {
		if len(secretPath.RelatedWorkloads) == 0 {
			continue
		}
		if secretPath.RelatedWorkloads[0] != workloadLabel {
			continue
		}
		if secretPath.LikelySecretType == "service-account token" || secretPath.LikelySecretType == "projected service-account token" {
			return secretPath.ID, true
		}
	}
	return "", false
}

func strongestWorkloadForPatchSurface(
	namespace string,
	surface string,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (model.WorkloadPath, model.ServiceAccountPath, bool) {
	workloads := workloadByNamespace[namespace]
	bestIndex := -1
	bestScore := -1
	var bestServiceAccount model.ServiceAccountPath

	for index, workload := range workloads {
		if workload.Kind != "Pod" {
			continue
		}
		if !workloadHasVisiblePatchSurface(workload, surface) {
			continue
		}

		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		if serviceAccount.PowerSummary == "" {
			continue
		}

		score := triageScore(workload.Priority)
		if workload.PublicExposure {
			score += 10
		}
		if len(workload.RiskSignals) > 0 {
			score += 5
		}
		if score > bestScore {
			bestScore = score
			bestIndex = index
			bestServiceAccount = serviceAccount
		}
	}

	if bestIndex == -1 {
		return model.WorkloadPath{}, model.ServiceAccountPath{}, false
	}
	return workloads[bestIndex], bestServiceAccount, true
}

type serviceAccountSwitchOption struct {
	Workload              model.WorkloadPath
	CurrentServiceAccount model.ServiceAccountPath
	StrongerCandidates    []model.ServiceAccountPath
	ExactCandidate        *model.ServiceAccountPath
}

type serviceAccountSwitchRecordInputs struct {
	ChainID                 string
	Priority                string
	InternalProofState      string
	VisibilityTier          string
	PathType                string
	StartingFoothold        string
	SourceAsset             string
	SourceNamespace         string
	SubversionPoint         string
	LikelyKubernetesControl string
	Urgency                 string
	WhyStopHere             string
	ConfidenceBoundary      string
	NextReview              string
	Summary                 string
	MissingConfirmation     string
	EvidenceCommands        []string
	RelatedIDs              []string
}

func buildServiceAccountSwitchRecord(inputs serviceAccountSwitchRecordInputs) model.ChainPathRecord {
	return model.ChainPathRecord{
		ChainID:                 inputs.ChainID,
		Priority:                inputs.Priority,
		InternalProofState:      inputs.InternalProofState,
		VisibilityTier:          inputs.VisibilityTier,
		PathType:                inputs.PathType,
		StartingFoothold:        inputs.StartingFoothold,
		SourceAsset:             inputs.SourceAsset,
		SourceNamespace:         inputs.SourceNamespace,
		SubversionPoint:         inputs.SubversionPoint,
		LikelyKubernetesControl: inputs.LikelyKubernetesControl,
		Urgency:                 inputs.Urgency,
		WhyStopHere:             inputs.WhyStopHere,
		ConfidenceBoundary:      inputs.ConfidenceBoundary,
		NextReview:              inputs.NextReview,
		Summary:                 inputs.Summary,
		MissingConfirmation:     inputs.MissingConfirmation,
		EvidenceCommands:        append([]string(nil), inputs.EvidenceCommands...),
		RelatedIDs:              append([]string(nil), inputs.RelatedIDs...),
	}
}

func strongestWorkloadForServiceAccountSwitch(
	permission model.PermissionPath,
	namespace string,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (serviceAccountSwitchOption, bool) {
	workloads := workloadByNamespace[namespace]
	bestIndex := -1
	bestScore := -1
	var bestCurrent model.ServiceAccountPath
	var bestCandidates []model.ServiceAccountPath

	for index, workload := range workloads {
		if !permissionAppliesToServiceAccountSwitchWorkload(permission, workload) {
			continue
		}
		if !workloadHasVisiblePatchSurface(workload, "service account") {
			continue
		}

		current := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		candidates := strongerVisibleServiceAccountCandidates(workload, workloads, serviceAccountByKey)
		if len(candidates) == 0 {
			continue
		}

		score := triageScore(workload.Priority) + candidates[0].PowerRank
		if workload.PublicExposure {
			score += 10
		}
		if len(workload.RiskSignals) > 0 {
			score += 5
		}

		if score > bestScore {
			bestIndex = index
			bestScore = score
			bestCurrent = current
			bestCandidates = candidates
		}
	}

	if bestIndex == -1 {
		return serviceAccountSwitchOption{}, false
	}

	return serviceAccountSwitchOption{
		Workload:              workloads[bestIndex],
		CurrentServiceAccount: bestCurrent,
		StrongerCandidates:    append([]model.ServiceAccountPath(nil), bestCandidates...),
		ExactCandidate:        uniqueStrongestServiceAccountCandidate(bestCandidates),
	}, true
}

func uniqueStrongestServiceAccountCandidate(candidates []model.ServiceAccountPath) *model.ServiceAccountPath {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		candidate := candidates[0]
		return &candidate
	}

	topRank := candidates[0].PowerRank
	topCount := 0
	var chosen model.ServiceAccountPath
	for _, candidate := range candidates {
		if candidate.PowerRank != topRank {
			break
		}
		topCount++
		chosen = candidate
	}
	if topCount != 1 {
		return nil
	}
	return &chosen
}

func permissionAppliesToServiceAccountSwitchWorkload(permission model.PermissionPath, workload model.WorkloadPath) bool {
	switch permission.TargetGroup {
	case "pods":
		return workload.Kind == "Pod"
	case "workload-controllers":
		return workload.Kind != "" && workload.Kind != "Pod"
	default:
		return false
	}
}

func strongerVisibleServiceAccountCandidates(
	workload model.WorkloadPath,
	workloads []model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ServiceAccountPath {
	current := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
	candidates := []model.ServiceAccountPath{}
	seen := map[string]bool{}

	for _, candidateWorkload := range workloads {
		candidate := serviceAccountByKey[candidateWorkload.Namespace+"/"+candidateWorkload.ServiceAccountName]
		if candidate.Namespace != workload.Namespace || candidate.Name == "" {
			continue
		}
		if candidate.Name == workload.ServiceAccountName {
			continue
		}
		if candidate.PowerSummary == "" || candidate.EvidenceStatus != "direct" {
			continue
		}
		if candidate.PowerRank <= current.PowerRank {
			continue
		}

		key := candidate.Namespace + "/" + candidate.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		candidates = append(candidates, candidate)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		leftScore := candidates[i].PowerRank
		rightScore := candidates[j].PowerRank
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		if chainPriorityOrder(candidates[i].Priority) != chainPriorityOrder(candidates[j].Priority) {
			return chainPriorityOrder(candidates[i].Priority) < chainPriorityOrder(candidates[j].Priority)
		}
		if candidates[i].Namespace != candidates[j].Namespace {
			return candidates[i].Namespace < candidates[j].Namespace
		}
		return candidates[i].Name < candidates[j].Name
	})
	return candidates
}

func permissionSupportsExactWorkloadPatchSurface(permission model.PermissionPath) bool {
	if permission.TargetGroup != "pods" {
		return false
	}
	switch permission.ActionVerb {
	case "patch", "update":
		return true
	default:
		return false
	}
}

func exactPatchSurfaceCandidates() []string {
	return []string{
		"image",
		"command",
		"args",
		"env",
		"mounted secret refs",
		"mounted config refs",
		"init containers",
	}
}

func exactPatchSurfaceChainIDPart(surface string) string {
	return strings.ReplaceAll(surface, " ", "-")
}

func permissionSupportsServiceAccountRepointing(permission model.PermissionPath) bool {
	switch permission.TargetGroup {
	case "pods", "workload-controllers":
	default:
		return false
	}
	switch permission.ActionVerb {
	case "patch", "update":
		return true
	default:
		return false
	}
}

func workloadChangePermissionScore(permission model.PermissionPath) int {
	switch permission.ActionVerb {
	case "patch":
		return 2
	case "update":
		return 1
	default:
		return 0
	}
}

func workloadHasVisiblePatchSurface(workload model.WorkloadPath, surface string) bool {
	for _, visibleSurface := range workloadPatchRelevantFields(workload) {
		if visibleSurface == surface {
			return true
		}
	}
	return false
}

func workloadPatchRelevantFields(workload model.WorkloadPath) []string {
	if len(workload.PatchRelevantFields) > 0 {
		return workload.PatchRelevantFields
	}
	return workload.VisiblePatchSurfaces
}

func exactPatchSurfaceSubversionPoint(actionVerb string, workloadLabel string, surface string) string {
	switch actionVerb {
	case "update":
		return "update " + surface + " on workload " + workloadLabel
	default:
		return "patch " + surface + " on workload " + workloadLabel
	}
}

func namespacedServiceAccountLabel(namespace string, name string) string {
	if namespace == "" || name == "" {
		return ""
	}
	return namespace + "/" + name
}

func boundedServiceAccountControlSummary(candidates []model.ServiceAccountPath) string {
	if len(candidates) == 0 {
		return "stronger visible service-account paths are present in this namespace"
	}

	summaries := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.PowerSummary == "" || seen[candidate.PowerSummary] {
			continue
		}
		seen[candidate.PowerSummary] = true
		summaries = append(summaries, candidate.PowerSummary)
	}
	if len(summaries) == 0 {
		return "stronger visible service-account paths are present in this namespace"
	}
	return "visible replacement identities include " + strings.Join(summaries, ", ")
}

func sortedStringKeys[T any](mapping map[string]T) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func triageScore(priority string) int {
	switch priority {
	case "high":
		return 30
	case "medium":
		return 20
	case "low":
		return 10
	default:
		return 0
	}
}

func chainPriorityOrder(priority string) int {
	switch priority {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func visibilityTierRank(tier string) int {
	switch tier {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func chainPathTypeRank(pathType string) int {
	switch pathType {
	case "direct control visible":
		return 0
	case "workload pivot":
		return 1
	case "direct control not confirmed":
		return 2
	case "visibility blocked":
		return 3
	default:
		return 4
	}
}

func namespaceScope(scope string) (string, bool) {
	const prefix = "namespace/"
	if strings.HasPrefix(scope, prefix) {
		namespace := strings.TrimPrefix(scope, prefix)
		return namespace, namespace != ""
	}
	return "", false
}
