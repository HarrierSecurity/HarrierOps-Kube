package chains

import (
	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
)

func BuildScaffoldOutput(metadata contracts.Metadata, selectedFamily string) (model.ChainsScaffoldOutput, error) {
	families, err := FamilyDescriptors(selectedFamily)
	if err != nil {
		return model.ChainsScaffoldOutput{}, err
	}

	var selected *string
	if selectedFamily != "" {
		selected = &selectedFamily
	}

	return model.ChainsScaffoldOutput{
		Metadata:               metadata,
		GroupedCommandName:     GroupedCommandName,
		CommandState:           "scaffold",
		CurrentBehavior:        CurrentBehavior(),
		PlannedInputModes:      GroupedCommandInputModes(),
		PreferredArtifactOrder: PreferredArtifactOrder(),
		SelectedFamily:         selected,
		Families:               families,
		Issues:                 []model.Issue{},
	}, nil
}
