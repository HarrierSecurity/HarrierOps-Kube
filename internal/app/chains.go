package app

import (
	"harrierops-kube/internal/chains"
	"harrierops-kube/internal/model"
)

func buildChainsPayload(selectedFamily string) (map[string]any, error) {
	output, err := chains.BuildScaffoldOutput(buildMetadata(chains.GroupedCommandName, model.MetadataContext{}, ""), selectedFamily)
	if err != nil {
		return nil, err
	}
	return structToMap(output)
}
