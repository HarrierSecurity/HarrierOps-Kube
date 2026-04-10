package chains

import "strings"

const workloadPatchWhyStopHere = "current foothold can change an already running workload with stronger identity"

var workloadPatchSurfaceOrder = []string{
	"image",
	"command",
	"args",
	"env",
	"service account",
	"mounted secret refs",
	"mounted config refs",
	"init containers",
	"sidecars",
	"replicas",
}

func WorkloadPatchWhyStopHere() string {
	return workloadPatchWhyStopHere
}

func FormatWorkloadPatchConfidenceBoundary(visiblePatchSurfaces []string) (string, bool) {
	ordered := orderedVisiblePatchSurfaces(visiblePatchSurfaces)
	if len(ordered) == 0 {
		return "", false
	}

	// Keep the boundary positive and evidence-bound: list only visible change surfaces.
	return "Current scope confirms these workload fields are changeable: " + strings.Join(ordered, ", ") + ".", true
}

func orderedVisiblePatchSurfaces(visiblePatchSurfaces []string) []string {
	if len(visiblePatchSurfaces) == 0 {
		return nil
	}

	visible := make(map[string]bool, len(visiblePatchSurfaces))
	for _, surface := range visiblePatchSurfaces {
		visible[surface] = true
	}

	ordered := make([]string, 0, len(visible))
	for _, surface := range workloadPatchSurfaceOrder {
		if visible[surface] {
			ordered = append(ordered, surface)
		}
	}
	return ordered
}
