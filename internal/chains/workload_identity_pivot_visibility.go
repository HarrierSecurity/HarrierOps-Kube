package chains

type WorkloadIdentityVisibilityInputs struct {
	WorkloadVisible         bool
	SubversionPointVisible  bool
	AttachedIdentityVisible bool
	StrongerControlVisible  bool
	VisibleChangeSurfaces   bool
	ExactBlockerKnown       bool
	NextReviewSet           bool
}

type WorkloadIdentityVisibility struct {
	Tier            string
	OperatorWording string
	SuppressDefault bool
}

func ClassifyWorkloadIdentityVisibility(inputs WorkloadIdentityVisibilityInputs) (WorkloadIdentityVisibility, bool) {
	if !inputs.WorkloadVisible {
		return WorkloadIdentityVisibility{}, false
	}

	if inputs.SubversionPointVisible && inputs.AttachedIdentityVisible && inputs.StrongerControlVisible {
		wording := "Current scope can see the workload-side lever, the stronger identity, and the downstream control behind this path."
		if inputs.VisibleChangeSurfaces {
			wording = "Current scope can see the workload-side lever, the stronger identity, the downstream control behind this path, and the visible change surfaces on the workload."
		}
		return WorkloadIdentityVisibility{
			Tier:            "high",
			OperatorWording: wording,
			SuppressDefault: false,
		}, true
	}

	if inputs.AttachedIdentityVisible && (inputs.SubversionPointVisible || inputs.StrongerControlVisible) {
		wording := "Current scope can see most of this workload-linked path, but one side still needs bounded follow-up."
		switch {
		case !inputs.SubversionPointVisible:
			wording = "Current scope can see the workload and stronger identity story, but it does not yet show the exact workload-side lever."
		case !inputs.StrongerControlVisible:
			wording = "Current scope can see the workload-side lever and attached identity, but it does not yet show the strongest downstream control."
		}
		return WorkloadIdentityVisibility{
			Tier:            "medium",
			OperatorWording: wording,
			SuppressDefault: false,
		}, true
	}

	wording := "Current scope can see a workload-linked clue, but not enough surrounding path detail to treat it like a default pivot."
	if inputs.ExactBlockerKnown {
		wording = "Current scope can see a workload-linked clue, but visibility is still too thin to treat it like a default pivot until that blocker is cleared."
	}

	return WorkloadIdentityVisibility{
		Tier:            "low",
		OperatorWording: wording,
		SuppressDefault: !(inputs.ExactBlockerKnown && inputs.NextReviewSet),
	}, true
}
