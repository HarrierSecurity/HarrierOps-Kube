package chains

import (
	"fmt"

	"harrierops-kube/internal/model"
)

const GroupedCommandName = "chains"

var groupedCommandInputModes = []string{"live", "artifacts"}
var preferredArtifactOrder = []string{"loot", "json"}

const currentBehavior = "Family overview and grouped runner. Use `harrierops-kube chains` to review path families, then `harrierops-kube chains <family>` to run one family from current scope."

type SourceSpec struct {
	Command       string
	MinimumFields []string
	Rationale     string
}

type FamilySpec struct {
	Name                string
	State               string
	Meaning             string
	Summary             string
	AllowedClaim        string
	CurrentGap          string
	BestCurrentExamples []string
	PlannedRowShape     []string
	PathTypeGuide       []model.ChainPathTypeGuide
	InternalProofLadder []model.ChainProofState
	SourceCommands      []SourceSpec
}

var familySpecs = []FamilySpec{
	{
		Name:         "workload-identity-pivot",
		State:        "implemented",
		Meaning:      "A current foothold can likely influence a workload or workload-linked service account that already carries stronger downstream control.",
		Summary:      "Follow the shortest visible workload-to-identity pivot toward stronger service-account-backed Kubernetes control.",
		AllowedClaim: "Can claim that visible workload, service-account, permission, privesc, and secret evidence suggests a credible workload-linked identity pivot. Cannot claim successful execution, token use, stronger control, or sidecar insertion without the explicit control edge and confirmation basis.",
		CurrentGap:   WorkloadIdentityPivotCurrentGap(),
		BestCurrentExamples: []string{
			"workloads -> service-accounts -> permissions",
			"workloads -> service-accounts -> privesc",
			"secrets -> workloads -> service-accounts",
		},
		PlannedRowShape: []string{
			"priority",
			"workload",
			"subversion_point",
			"path_type",
			"likely_kubernetes_control",
			"urgency",
			"why_stop_here",
			"confidence_boundary",
			"next_review",
		},
		PathTypeGuide: []model.ChainPathTypeGuide{
			{
				Name:              "direct control visible",
				Meaning:           "Current access likely lets the operator change or enter the workload, and the attached service account already changes the next move.",
				DefaultNextReview: "permissions",
				PriorityIntent:    "highest-value default row type",
			},
			{
				Name:              "workload pivot",
				Meaning:           "The workload-linked service account path is visible and meaningful, but the stronger control story still depends on deeper workload-side validation.",
				DefaultNextReview: "workloads",
				PriorityIntent:    "below direct control visible, above visibility-limited rows",
			},
			{
				Name:              "direct control not confirmed",
				Meaning:           "The attached service account looks stronger, but current access does not yet prove the workload-side action that would make the path immediate.",
				DefaultNextReview: "service-accounts",
				PriorityIntent:    "mid-tier row type when the stronger identity is clear but the action edge is not",
			},
			{
				Name:              "visibility blocked",
				Meaning:           "A real workload-linked identity clue survives, but current scope does not confirm enough of the stronger path to raise it honestly.",
				DefaultNextReview: "permissions",
				PriorityIntent:    "lowest default row type unless the blocked clue still carries unusually strong operator value",
			},
		},
		InternalProofLadder: []model.ChainProofState{
			{
				State:   "visible",
				Meaning: "The workload-linked clue is real enough to keep on screen, but the stronger identity or usable action is not yet confirmed.",
			},
			{
				State:   "target-confirmed",
				Meaning: "The workload, attached service account, and stronger downstream control are clear, but the current session's practical workload-side action is not yet confirmed.",
			},
			{
				State:   "path-confirmed",
				Meaning: "The workload-side action, attached service account, and stronger downstream control connect strongly enough to treat the row as a real path.",
			},
			{
				State:   "blocked",
				Meaning: "Current scope does not show enough evidence to keep the row as an honest workload-identity path.",
			},
		},
		SourceCommands: []SourceSpec{
			{
				Command: "workloads",
				MinimumFields: []string{
					"id",
					"name",
					"namespace",
					"service_account_name",
					"patch_relevant_fields",
					"related_exposures",
					"public_exposure",
					"service_account_power",
					"priority",
				},
				Rationale: "Provides the workload-side insertion point, exposure context, attached service account, and the visible change surfaces that could make a workload patch row operator-complete.",
			},
			{
				Command: "service-accounts",
				MinimumFields: []string{
					"id",
					"name",
					"namespace",
					"related_workloads",
					"exposed_workloads",
					"power_summary",
					"token_posture",
					"priority",
				},
				Rationale: "Provides the workload-linked identity anchor, reuse breadth, token posture, and the concrete power that makes the service account worth chaining.",
			},
			{
				Command: "permissions",
				MinimumFields: []string{
					"id",
					"subject",
					"action_summary",
					"scope",
					"evidence_status",
					"related_bindings",
					"priority",
					"next_review",
				},
				Rationale: "Provides the current-session action edge when the present foothold can already drive workload or identity change.",
			},
			{
				Command: "privesc",
				MinimumFields: []string{
					"id",
					"starting_foothold",
					"path_class",
					"action",
					"stronger_outcome",
					"confidence",
					"operator_signal",
					"what_is_proven",
					"what_is_missing",
					"next_review",
				},
				Rationale: "Provides the current-foothold escalation cues that the first chain family can harden into a defended workload-linked path story.",
			},
			{
				Command: "secrets",
				MinimumFields: []string{
					"id",
					"secret_story",
					"source_surface",
					"subject",
					"related_workloads",
					"direct_use_confidence",
					"trust_path",
					"operator_signal",
					"priority",
					"next_review",
				},
				Rationale: "Provides secret-bearing trust paths that can corroborate why a workload-linked identity path matters now versus later.",
			},
		},
	},
}

func GroupedCommandInputModes() []string {
	return append([]string(nil), groupedCommandInputModes...)
}

func PreferredArtifactOrder() []string {
	return append([]string(nil), preferredArtifactOrder...)
}

func CurrentBehavior() string {
	return currentBehavior
}

func FamilyNames() []string {
	names := make([]string, 0, len(familySpecs))
	for _, spec := range familySpecs {
		names = append(names, spec.Name)
	}
	return names
}

func ImplementedFamilyNames() []string {
	names := make([]string, 0, len(familySpecs))
	for _, spec := range familySpecs {
		if spec.State == "implemented" {
			names = append(names, spec.Name)
		}
	}
	return names
}

func FamilySpecFor(name string) (FamilySpec, bool) {
	for _, spec := range familySpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return FamilySpec{}, false
}

func FamilyDescriptors(selectedFamily string) ([]model.ChainFamilyDescriptor, error) {
	specs := familySpecs
	if selectedFamily != "" {
		spec, ok := FamilySpecFor(selectedFamily)
		if !ok {
			return nil, fmt.Errorf("unknown chain family %q", selectedFamily)
		}
		specs = []FamilySpec{spec}
	}

	descriptors := make([]model.ChainFamilyDescriptor, 0, len(specs))
	for _, spec := range specs {
		descriptors = append(descriptors, descriptorFromSpec(spec))
	}
	return descriptors, nil
}

func descriptorFromSpec(spec FamilySpec) model.ChainFamilyDescriptor {
	sourceCommands := make([]model.ChainSourceDescriptor, 0, len(spec.SourceCommands))
	for _, source := range spec.SourceCommands {
		sourceCommands = append(sourceCommands, model.ChainSourceDescriptor{
			Command:       source.Command,
			MinimumFields: append([]string(nil), source.MinimumFields...),
			Rationale:     source.Rationale,
		})
	}

	return model.ChainFamilyDescriptor{
		Family:              spec.Name,
		State:               spec.State,
		Meaning:             spec.Meaning,
		Summary:             spec.Summary,
		AllowedClaim:        spec.AllowedClaim,
		CurrentGap:          spec.CurrentGap,
		BestCurrentExamples: append([]string(nil), spec.BestCurrentExamples...),
		PlannedRowShape:     append([]string(nil), spec.PlannedRowShape...),
		PathTypeGuide:       append([]model.ChainPathTypeGuide(nil), spec.PathTypeGuide...),
		InternalProofLadder: append([]model.ChainProofState(nil), spec.InternalProofLadder...),
		SourceCommands:      sourceCommands,
	}
}
