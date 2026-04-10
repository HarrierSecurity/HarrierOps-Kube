package chains

import (
	"reflect"
	"strings"
	"testing"

	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
)

func TestRegistryUsesExpectedGroupedCommandShape(t *testing.T) {
	if GroupedCommandName != "chains" {
		t.Fatalf("GroupedCommandName = %q, want chains", GroupedCommandName)
	}
	if got := GroupedCommandInputModes(); !reflect.DeepEqual(got, []string{"live", "artifacts"}) {
		t.Fatalf("GroupedCommandInputModes() = %#v", got)
	}
	if got := PreferredArtifactOrder(); !reflect.DeepEqual(got, []string{"loot", "json"}) {
		t.Fatalf("PreferredArtifactOrder() = %#v", got)
	}
}

func TestRegistryKeepsFirstFamilyOrder(t *testing.T) {
	if got := FamilyNames(); !reflect.DeepEqual(got, []string{"workload-identity-pivot"}) {
		t.Fatalf("FamilyNames() = %#v", got)
	}
}

func TestRegistryImplementedStateDrivesRunnableFamilies(t *testing.T) {
	if got := ImplementedFamilyNames(); !reflect.DeepEqual(got, []string{"workload-identity-pivot"}) {
		t.Fatalf("ImplementedFamilyNames() = %#v, want workload-identity-pivot", got)
	}
}

func TestScaffoldFieldsExistOnBackingModels(t *testing.T) {
	modelFields := map[string]map[string]struct{}{
		"workloads":        jsonFieldSet(reflect.TypeOf(model.WorkloadPath{})),
		"service-accounts": jsonFieldSet(reflect.TypeOf(model.ServiceAccountPath{})),
		"permissions":      jsonFieldSet(reflect.TypeOf(model.PermissionPath{})),
		"privesc":          jsonFieldSet(reflect.TypeOf(model.PrivescPath{})),
		"secrets":          jsonFieldSet(reflect.TypeOf(model.SecretPath{})),
	}

	for _, familyName := range FamilyNames() {
		spec, ok := FamilySpecFor(familyName)
		if !ok {
			t.Fatalf("missing FamilySpecFor(%q)", familyName)
		}
		for _, source := range spec.SourceCommands {
			fields, ok := modelFields[source.Command]
			if !ok {
				t.Fatalf("missing field set for source command %q", source.Command)
			}
			for _, fieldName := range source.MinimumFields {
				if _, ok := fields[fieldName]; !ok {
					t.Fatalf("source command %q missing field %q in registry", source.Command, fieldName)
				}
			}
		}
	}
}

func TestBuildScaffoldOutputReturnsSelectedFamilyOnly(t *testing.T) {
	output, err := BuildScaffoldOutput(contracts.Metadata{Command: "chains"}, "workload-identity-pivot")
	if err != nil {
		t.Fatalf("BuildScaffoldOutput() error = %v", err)
	}

	if output.Metadata.Command != "chains" {
		t.Fatalf("metadata.command = %q, want chains", output.Metadata.Command)
	}
	if output.GroupedCommandName != "chains" {
		t.Fatalf("grouped_command_name = %q, want chains", output.GroupedCommandName)
	}
	if output.CommandState != "scaffold" {
		t.Fatalf("command_state = %q, want scaffold", output.CommandState)
	}
	if output.SelectedFamily == nil || *output.SelectedFamily != "workload-identity-pivot" {
		t.Fatalf("selected_family = %#v", output.SelectedFamily)
	}
	if len(output.Families) != 1 {
		t.Fatalf("len(families) = %d, want 1", len(output.Families))
	}
	if output.Families[0].State != "implemented" {
		t.Fatalf("family state = %q, want implemented", output.Families[0].State)
	}
	if !reflect.DeepEqual(output.Families[0].PlannedRowShape, []string{
		"priority",
		"workload",
		"subversion_point",
		"path_type",
		"likely_kubernetes_control",
		"urgency",
		"why_stop_here",
		"confidence_boundary",
		"next_review",
	}) {
		t.Fatalf("planned_row_shape = %#v", output.Families[0].PlannedRowShape)
	}
	if len(output.Families[0].PathTypeGuide) == 0 {
		t.Fatal("path_type_guide = empty, want deterministic operator-facing row types")
	}
	if len(output.Families[0].InternalProofLadder) != 4 {
		t.Fatalf("internal_proof_ladder = %#v, want 4-state proof ladder", output.Families[0].InternalProofLadder)
	}
}

func TestBuildScaffoldOutputRejectsUnknownFamily(t *testing.T) {
	if _, err := BuildScaffoldOutput(contracts.Metadata{Command: "chains"}, "banana-path"); err == nil {
		t.Fatal("BuildScaffoldOutput() error = nil, want unknown family error")
	} else if !strings.Contains(err.Error(), "unknown chain family") {
		t.Fatalf("error = %q, want unknown chain family", err)
	}
}

func jsonFieldSet(typeValue reflect.Type) map[string]struct{} {
	fields := make(map[string]struct{}, typeValue.NumField())
	for index := 0; index < typeValue.NumField(); index++ {
		tag := typeValue.Field(index).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}
