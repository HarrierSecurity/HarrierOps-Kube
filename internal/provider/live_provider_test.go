package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestParseServiceAccountSubject(t *testing.T) {
	label, namespace, name, ok := parseServiceAccountSubject("system:serviceaccount:payments:api")
	if !ok {
		t.Fatal("parseServiceAccountSubject() = false, want true")
	}
	if label != "system:serviceaccount:payments:api" {
		t.Fatalf("label = %q", label)
	}
	if namespace != "payments" {
		t.Fatalf("namespace = %q", namespace)
	}
	if name != "api" {
		t.Fatalf("name = %q", name)
	}
}

func TestTokenSubjectFromSessionDecodesBearerToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"system:serviceaccount:payments:api"}`))
	token := "header." + payload + ".sig"

	subject := tokenSubjectFromSession(liveSession{
		restConfig: &rest.Config{
			BearerToken: token,
		},
	})
	if subject != "system:serviceaccount:payments:api" {
		t.Fatalf("subject = %q", subject)
	}
}

func TestWorkloadFromPodCapturesVisiblePatchSurfacesAndRiskSignals(t *testing.T) {
	privileged := true
	allowPrivilegeEscalation := true
	runAsUser := int64(0)
	automount := true

	workload := workloadFromPod(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fox-admin",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "fox-admin",
			AutomountServiceAccountToken: &automount,
			HostNetwork:                  true,
			Volumes: []corev1.Volume{
				{
					Name: "docker-sock",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"},
					},
				},
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "fox-admin-config"},
						},
					},
				},
				{
					Name: "secret",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "fox-admin-token"},
					},
				},
			},
			InitContainers: []corev1.Container{
				{Name: "init-permissions"},
			},
			Containers: []corev1.Container{
				{
					Name:    "main",
					Image:   "ghcr.io/example/fox-admin:latest",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c"},
					Env: []corev1.EnvVar{
						{Name: "AZURE_CLIENT_ID"},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               &privileged,
						AllowPrivilegeEscalation: &allowPrivilegeEscalation,
						RunAsUser:                &runAsUser,
					},
				},
				{
					Name:  "log-shipper",
					Image: "fluentbit:latest",
				},
			},
		},
	})

	if workload.ServiceAccountName != "fox-admin" {
		t.Fatalf("ServiceAccountName = %q", workload.ServiceAccountName)
	}
	if len(workload.Command) == 0 || workload.Command[0] != "/bin/sh" {
		t.Fatalf("Command = %#v", workload.Command)
	}
	if len(workload.Args) == 0 || workload.Args[0] != "-c" {
		t.Fatalf("Args = %#v", workload.Args)
	}
	if len(workload.EnvNames) == 0 || workload.EnvNames[0] != "AZURE_CLIENT_ID" {
		t.Fatalf("EnvNames = %#v", workload.EnvNames)
	}
	if !workload.Privileged || !workload.AllowPrivilegeEscalation || !workload.RunsAsRoot {
		t.Fatalf("security flags = privileged:%v allowPrivilegeEscalation:%v runsAsRoot:%v", workload.Privileged, workload.AllowPrivilegeEscalation, workload.RunsAsRoot)
	}
	if !workload.DockerSocketMount {
		t.Fatal("DockerSocketMount = false, want true")
	}
	if len(workload.MountedSecretRefs) == 0 || workload.MountedSecretRefs[0] != "fox-admin-token" {
		t.Fatalf("MountedSecretRefs = %#v", workload.MountedSecretRefs)
	}
	if len(workload.MountedConfigRefs) == 0 || workload.MountedConfigRefs[0] != "fox-admin-config" {
		t.Fatalf("MountedConfigRefs = %#v", workload.MountedConfigRefs)
	}
	if len(workload.InitContainers) == 0 || workload.InitContainers[0] != "init-permissions" {
		t.Fatalf("InitContainers = %#v", workload.InitContainers)
	}
	if len(workload.Sidecars) == 0 || workload.Sidecars[0] != "log-shipper" {
		t.Fatalf("Sidecars = %#v", workload.Sidecars)
	}
}

func TestWorkloadFromTemplateCapturesControllerShape(t *testing.T) {
	replicas := 3
	automount := true

	workload := workloadFromTemplate(
		"Deployment",
		"storefront",
		"web",
		corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				ServiceAccountName:           "web",
				AutomountServiceAccountToken: &automount,
				Containers: []corev1.Container{
					{
						Name:    "main",
						Image:   "ghcr.io/example/web:v1",
						Command: []string{"/app/server"},
						Args:    []string{"--port=8080"},
						Env: []corev1.EnvVar{
							{Name: "APP_MODE"},
						},
					},
					{
						Name:  "log-shipper",
						Image: "fluentbit:latest",
					},
				},
			},
		},
		&replicas,
	)

	if workload.ID != "deployment:storefront:web" {
		t.Fatalf("ID = %q", workload.ID)
	}
	if workload.Kind != "Deployment" {
		t.Fatalf("Kind = %q", workload.Kind)
	}
	if workload.Replicas == nil || *workload.Replicas != 3 {
		t.Fatalf("Replicas = %#v", workload.Replicas)
	}
	if len(workload.EnvNames) != 1 || workload.EnvNames[0] != "APP_MODE" {
		t.Fatalf("EnvNames = %#v", workload.EnvNames)
	}
	if len(workload.Sidecars) != 1 || workload.Sidecars[0] != "log-shipper" {
		t.Fatalf("Sidecars = %#v", workload.Sidecars)
	}
}

func TestCollectLiveWorkloadSnapshotPrefersVisibleDeploymentTemplate(t *testing.T) {
	replicas := int32(2)
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web",
				Namespace: "storefront",
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						ServiceAccountName: "web",
						Containers: []corev1.Container{
							{
								Name:  "main",
								Image: "ghcr.io/example/web:v1",
								Env: []corev1.EnvVar{
									{Name: "APP_MODE"},
								},
							},
						},
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-7d9f5b7f6d",
				Namespace: "storefront",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Deployment", Name: "web"},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-7d9f5b7f6d-abcde",
				Namespace: "storefront",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: "web-7d9f5b7f6d"},
				},
				Labels: map[string]string{"app": "web"},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "web",
				Containers: []corev1.Container{
					{
						Name:  "main",
						Image: "ghcr.io/example/web:v1",
						Env: []corev1.EnvVar{
							{Name: "APP_MODE"},
							{Name: "RUNTIME_INJECTED"},
						},
					},
				},
			},
		},
	)

	snapshot, err := collectLiveWorkloadSnapshot(liveSession{
		client:             client,
		effectiveNamespace: "storefront",
	}, QueryOptions{})
	if err != nil {
		t.Fatalf("collectLiveWorkloadSnapshot() error = %v", err)
	}

	if len(snapshot.Workloads) != 1 {
		t.Fatalf("len(Workloads) = %d, want 1", len(snapshot.Workloads))
	}

	workload := snapshot.Workloads[0]
	if workload.ID != "deployment:storefront:web" {
		t.Fatalf("ID = %q", workload.ID)
	}
	if workload.Kind != "Deployment" {
		t.Fatalf("Kind = %q", workload.Kind)
	}
	if len(workload.EnvNames) != 1 || workload.EnvNames[0] != "APP_MODE" {
		t.Fatalf("EnvNames = %#v, want controller template env only", workload.EnvNames)
	}
	if label := snapshot.PodWorkloadLabels["storefront/web-7d9f5b7f6d-abcde"]; label != "storefront/web" {
		t.Fatalf("PodWorkloadLabels[pod] = %q", label)
	}
}

func TestListPodsWithFallbackHonorsSessionContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := listPodsWithFallback(liveSession{
		client:             fake.NewSimpleClientset(),
		effectiveNamespace: "default",
		ctx:                ctx,
		cancel:             func() {},
	}, QueryOptions{Namespace: "default"}, "workloads.pods")
	if err == nil {
		t.Fatal("listPodsWithFallback() error = nil, want context cancellation")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("listPodsWithFallback() error = %q, want context canceled", err)
	}
}

func TestCollectLiveWorkloadSnapshotFallsBackToPodWhenControllerIsNotVisible(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-7d9f5b7f6d-abcde",
				Namespace: "storefront",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: "web-7d9f5b7f6d"},
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "web",
				Containers: []corev1.Container{
					{
						Name:  "main",
						Image: "ghcr.io/example/web:v1",
						Env: []corev1.EnvVar{
							{Name: "RUNTIME_ONLY"},
						},
					},
				},
			},
		},
	)

	snapshot, err := collectLiveWorkloadSnapshot(liveSession{
		client:             client,
		effectiveNamespace: "storefront",
	}, QueryOptions{})
	if err != nil {
		t.Fatalf("collectLiveWorkloadSnapshot() error = %v", err)
	}

	if len(snapshot.Workloads) != 1 {
		t.Fatalf("len(Workloads) = %d, want 1", len(snapshot.Workloads))
	}

	workload := snapshot.Workloads[0]
	if workload.ID != "pod:storefront:web-7d9f5b7f6d-abcde" {
		t.Fatalf("ID = %q", workload.ID)
	}
	if workload.Kind != "Pod" {
		t.Fatalf("Kind = %q", workload.Kind)
	}
	if len(workload.EnvNames) != 1 || workload.EnvNames[0] != "RUNTIME_ONLY" {
		t.Fatalf("EnvNames = %#v", workload.EnvNames)
	}
}

func TestWorkloadsForServiceUsesSelectorMatchedPods(t *testing.T) {
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-svc",
			Namespace: "storefront",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "web"},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-123",
				Namespace: "storefront",
				Labels:    map[string]string{"app": "web"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "jobs-1",
				Namespace: "storefront",
				Labels:    map[string]string{"app": "jobs"},
			},
		},
	}
	workloads := workloadsForService(service, pods, map[string]string{
		"storefront/web-123": "storefront/web-123",
		"storefront/jobs-1":  "storefront/jobs-1",
	})

	if len(workloads) != 1 || workloads[0] != "storefront/web-123" {
		t.Fatalf("workloads = %v, want storefront/web-123", workloads)
	}
}

func TestNamespaceFallbackIssueKeepsScopeAndNamespace(t *testing.T) {
	issue := namespaceFallbackIssue("workloads.pods", "payments")
	if issue.Scope != "workloads.pods" {
		t.Fatalf("Scope = %q", issue.Scope)
	}
	if issue.Kind != "collection" {
		t.Fatalf("Kind = %q", issue.Kind)
	}
	if want := "payments"; !strings.Contains(issue.Message, want) {
		t.Fatalf("Message = %q, want namespace %q", issue.Message, want)
	}
}

func TestIngressExternalTargetsIncludesHostsAndAddresses(t *testing.T) {
	ingress := corev1.LoadBalancerStatus{}
	_ = ingress
	targets := ingressExternalTargets(networkingFixture())
	if len(targets) != 2 {
		t.Fatalf("targets = %v", targets)
	}
	if targets[0] != "1.2.3.4" || targets[1] != "app.example.com" {
		t.Fatalf("targets = %v", targets)
	}
}

func networkingFixture() networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-ing",
			Namespace: "storefront",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{Host: "app.example.com"},
			},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{
					{IP: "1.2.3.4"},
				},
			},
		},
	}
}

func TestServiceExternalTargetsIncludesNodePort(t *testing.T) {
	targets := serviceExternalTargets(corev1.Service{
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{NodePort: 30080},
			},
		},
	})
	if len(targets) != 1 || targets[0] != fmt.Sprintf("nodePort:%d", 30080) {
		t.Fatalf("targets = %v", targets)
	}
}
