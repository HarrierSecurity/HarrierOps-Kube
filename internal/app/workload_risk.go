package app

import "harrierops-kube/internal/model"

func workloadRiskSignals(workload model.Workload) []string {
	signals := []string{}
	if workload.Privileged {
		signals = append(signals, "privileged")
	}
	if workload.AllowPrivilegeEscalation {
		signals = append(signals, "allows privilege escalation")
	}
	if workload.DockerSocketMount {
		signals = append(signals, "mounts docker socket")
	}
	if workload.HostNetwork || workload.HostPID || workload.HostIPC {
		signals = append(signals, "uses host namespaces")
	}
	if len(workload.HostPathMounts) > 0 {
		signals = append(signals, "mounts host paths")
	}
	if len(workload.AddedCapabilities) > 0 {
		signals = append(signals, "adds Linux capabilities")
	}
	if workload.RunsAsRoot {
		signals = append(signals, "runs as root")
	}
	return signals
}

func isRiskyWorkload(workload model.Workload) bool {
	return len(workloadRiskSignals(workload)) > 0
}
