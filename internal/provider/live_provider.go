package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"harrierops-kube/internal/model"
)

const (
	defaultNamespace              = "default"
	serviceAccountTokenFilePrefix = "/var/run/secrets/kubernetes.io/serviceaccount/"
	apiTimeout                    = 15 * time.Second
)

func NewLiveProvider() (Provider, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return liveProvider{loadingRules: loadingRules}, nil
}

type liveProvider struct {
	loadingRules *clientcmd.ClientConfigLoadingRules
}

type liveSession struct {
	client             kubernetes.Interface
	restConfig         *rest.Config
	rawConfig          clientcmdapi.Config
	currentContextName string
	effectiveNamespace string
	ctx                context.Context
	cancel             context.CancelFunc
}

func (p liveProvider) MetadataContext(options QueryOptions) (model.MetadataContext, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.MetadataContext{}, err
	}
	defer session.cancel()

	contextRef := session.rawConfig.Contexts[session.currentContextName]
	clusterName := ""
	if contextRef != nil {
		clusterName = contextRef.Cluster
	}

	return model.MetadataContext{
		ContextName: session.currentContextName,
		ClusterName: clusterName,
		Namespace:   session.effectiveNamespace,
	}, nil
}

func (p liveProvider) WhoAmI(options QueryOptions) (model.WhoAmIData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.WhoAmIData{}, err
	}
	defer session.cancel()

	contextRef := session.rawConfig.Contexts[session.currentContextName]
	clusterName := ""
	userName := ""
	server := ""
	if contextRef != nil {
		clusterName = contextRef.Cluster
		userName = contextRef.AuthInfo
		if clusterRef, ok := session.rawConfig.Clusters[contextRef.Cluster]; ok && clusterRef != nil {
			server = clusterRef.Server
		}
	}

	serverVersion := ""
	issues := []model.Issue{}
	version, versionErr := session.client.Discovery().ServerVersion()
	if versionErr == nil && version != nil {
		serverVersion = version.GitVersion
	} else {
		issues = append(issues, model.Issue{
			Kind:    "collection",
			Scope:   "whoami.server-version",
			Message: "Current scope could not confirm the Kubernetes server version from the API.",
		})
	}

	currentIdentity, identityEvidence, visibilityBlockers := deriveCurrentIdentity(session, userName)
	if currentIdentity.Confidence == "blocked" {
		issues = append(issues, model.Issue{
			Kind:    "visibility",
			Scope:   "whoami.identity",
			Message: "Current scope could not directly confirm the acting Kubernetes identity from visible auth material.",
		})
	}

	return model.WhoAmIData{
		KubeContext: model.KubeContext{
			CurrentContext: session.currentContextName,
			ClusterName:    clusterName,
			User:           userName,
			Namespace:      session.effectiveNamespace,
			Server:         server,
			ServerVersion:  serverVersion,
		},
		CurrentIdentity: currentIdentity,
		Session:         deriveSessionProfile(session, currentIdentity),
		EnvironmentHint: deriveLiveEnvironmentHint(server, clusterName),
		IdentityEvidence: func() []string {
			if len(identityEvidence) == 0 {
				return []string{"Current kubeconfig and visible auth material did not expose a directly attributable actor."}
			}
			return identityEvidence
		}(),
		VisibilityBlockers: visibilityBlockers,
		Issues:             issues,
	}, nil
}

func (p liveProvider) Inventory(options QueryOptions) (model.InventoryData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.InventoryData{}, err
	}
	defer session.cancel()

	counts := map[string]int{}
	issues := []model.Issue{}

	pods, podIssues, err := listPodsWithFallback(session, options, "inventory.pods")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, podIssues...)
	counts["pods"] = len(pods)

	deployments, deploymentIssues, err := listDeploymentsWithFallback(session, options, "inventory.deployments")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, deploymentIssues...)
	counts["deployments"] = len(deployments)

	daemonSets, daemonSetIssues, err := listDaemonSetsWithFallback(session, options, "inventory.daemonsets")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, daemonSetIssues...)
	counts["daemonsets"] = len(daemonSets)

	statefulSets, statefulSetIssues, err := listStatefulSetsWithFallback(session, options, "inventory.statefulsets")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, statefulSetIssues...)
	counts["statefulsets"] = len(statefulSets)

	serviceAccounts, saIssues, err := listServiceAccountsWithFallback(session, options, "inventory.serviceaccounts")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, saIssues...)
	counts["serviceaccounts"] = len(serviceAccounts)

	roleBindings, rbIssues, err := listRoleBindingsWithFallback(session, options, "inventory.rolebindings")
	if err != nil {
		return model.InventoryData{}, err
	}
	issues = append(issues, rbIssues...)
	counts["rolebindings"] = len(roleBindings)

	namespaces, err := session.client.CoreV1().Namespaces().List(session.ctx, metav1.ListOptions{})
	if err == nil {
		counts["namespaces"] = len(namespaces.Items)
	}

	nodes, err := session.client.CoreV1().Nodes().List(session.ctx, metav1.ListOptions{})
	if err == nil {
		counts["nodes"] = len(nodes.Items)
	}

	return model.InventoryData{
		KubernetesCounts: counts,
		DockerCounts:     map[string]int{},
		Issues:           issues,
	}, nil
}

func (p liveProvider) RBACBindings(options QueryOptions) (model.RBACData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.RBACData{}, err
	}
	defer session.cancel()

	clusterRoleBindings, err := session.client.RbacV1().ClusterRoleBindings().List(session.ctx, metav1.ListOptions{})
	if err != nil {
		return model.RBACData{}, fmt.Errorf("list cluster role bindings: %w", err)
	}

	clusterRoles, clusterRoleErr := session.client.RbacV1().ClusterRoles().List(session.ctx, metav1.ListOptions{})
	roleBindings, roleBindingIssues, roleBindingErr := listRoleBindingsWithFallback(session, options, "rbac.rolebindings")
	if roleBindingErr != nil {
		return model.RBACData{}, roleBindingErr
	}
	roles, roleIssues, roleErr := listRolesWithFallback(session, options, "rbac.roles")
	if roleErr != nil {
		return model.RBACData{}, roleErr
	}

	raw := rawRBACFixture{
		ClusterRoleBindings: make([]rawRoleBinding, 0, len(clusterRoleBindings.Items)),
		ClusterRoles:        make([]rawRole, 0, len(clusterRoles.Items)),
		RoleBindings:        make([]rawRoleBinding, 0, len(roleBindings)),
		Roles:               make([]rawRole, 0, len(roles)),
		Issues:              []model.Issue{},
	}

	raw.Issues = append(raw.Issues, roleBindingIssues...)
	raw.Issues = append(raw.Issues, roleIssues...)
	if clusterRoleErr != nil {
		raw.Issues = append(raw.Issues, model.Issue{
			Kind:    "collection",
			Scope:   "rbac.clusterroles",
			Message: "ClusterRole objects were not fully readable from current scope, so some cluster-wide role detail may be understated.",
		})
	}

	for _, binding := range clusterRoleBindings.Items {
		raw.ClusterRoleBindings = append(raw.ClusterRoleBindings, rawClusterRoleBindingFromLive(binding))
	}
	for _, binding := range roleBindings {
		raw.RoleBindings = append(raw.RoleBindings, rawRoleBindingFromLive(binding))
	}
	for _, role := range clusterRoles.Items {
		raw.ClusterRoles = append(raw.ClusterRoles, rawRoleFromClusterRole(role))
	}
	for _, role := range roles {
		raw.Roles = append(raw.Roles, rawRoleFromRole(role))
	}

	return normalizeRBACFixture(raw), nil
}

func (p liveProvider) ServiceAccounts(options QueryOptions) (model.ServiceAccountsData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.ServiceAccountsData{}, err
	}
	defer session.cancel()

	serviceAccounts, issues, err := listServiceAccountsWithFallback(session, options, "service-accounts")
	if err != nil {
		return model.ServiceAccountsData{}, err
	}

	rows := make([]model.ServiceAccount, 0, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		rows = append(rows, model.ServiceAccount{
			ID:                           "serviceaccount:" + serviceAccount.Namespace + ":" + serviceAccount.Name,
			Name:                         serviceAccount.Name,
			Namespace:                    serviceAccount.Namespace,
			AutomountServiceAccountToken: serviceAccount.AutomountServiceAccountToken,
			BoundRoles:                   []string{},
			ImagePullSecrets:             secretRefNames(serviceAccount.ImagePullSecrets),
			SecretNames:                  secretObjectRefNames(serviceAccount.Secrets),
		})
	}

	return model.ServiceAccountsData{
		ServiceAccounts: rows,
		Findings:        []model.Finding{},
		Issues:          issues,
	}, nil
}

func (p liveProvider) Workloads(options QueryOptions) (model.WorkloadsData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.WorkloadsData{}, err
	}
	defer session.cancel()

	snapshot, err := collectLiveWorkloadSnapshot(session, options)
	if err != nil {
		return model.WorkloadsData{}, err
	}

	return model.WorkloadsData{
		WorkloadAssets: snapshot.Workloads,
		Findings:       []model.Finding{},
		Issues:         snapshot.Issues,
	}, nil
}

func (p liveProvider) Exposures(options QueryOptions) (model.ExposureData, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return model.ExposureData{}, err
	}
	defer session.cancel()

	snapshot, err := collectLiveWorkloadSnapshot(session, options)
	if err != nil {
		return model.ExposureData{}, err
	}

	services, serviceIssues, err := listServicesWithFallback(session, options)
	if err != nil {
		return model.ExposureData{}, err
	}
	ingresses, ingressIssues, err := listIngressesWithFallback(session, options)
	if err != nil {
		return model.ExposureData{}, err
	}

	serviceRelatedWorkloads := map[string][]string{}
	rows := make([]model.Exposure, 0, len(services)+len(ingresses))
	for _, service := range services {
		relatedWorkloads := workloadsForService(service, snapshot.Pods, snapshot.PodWorkloadLabels)
		serviceRelatedWorkloads[service.Namespace+"/"+service.Name] = relatedWorkloads
		rows = append(rows, model.Exposure{
			ID:               "service:" + service.Namespace + ":" + service.Name,
			AssetType:        "Service",
			ExposureType:     serviceExposureType(service),
			Name:             service.Name,
			Namespace:        service.Namespace,
			Public:           serviceLooksPublic(service),
			ExternalTargets:  serviceExternalTargets(service),
			RelatedWorkloads: relatedWorkloads,
		})
	}

	for _, ingress := range ingresses {
		rows = append(rows, model.Exposure{
			ID:               "ingress:" + ingress.Namespace + ":" + ingress.Name,
			AssetType:        "Ingress",
			ExposureType:     "Ingress",
			Name:             ingress.Name,
			Namespace:        ingress.Namespace,
			Public:           true,
			ExternalTargets:  ingressExternalTargets(ingress),
			RelatedWorkloads: workloadsForIngress(ingress, serviceRelatedWorkloads),
		})
	}

	issues := append([]model.Issue{}, snapshot.Issues...)
	issues = append(issues, serviceIssues...)
	issues = append(issues, ingressIssues...)

	return model.ExposureData{
		ExposureAssets: rows,
		Findings:       []model.Finding{},
		Issues:         issues,
	}, nil
}

func (p liveProvider) CurrentSessionPermissions(options QueryOptions, currentIdentity model.CurrentIdentity) ([]model.PermissionPath, []model.Issue, error) {
	session, err := p.resolveSession(options)
	if err != nil {
		return nil, nil, err
	}
	defer session.cancel()
	if currentIdentity.Confidence == "blocked" || currentIdentity.Kind == "Unknown" {
		return nil, []model.Issue{{
			Kind:    "visibility",
			Scope:   "permissions.identity",
			Message: "Current session identity is not visible from current credentials, so current-foothold capability triage is incomplete.",
		}}, nil
	}

	subject := currentIdentity.Label + " (current session)"
	namespaces, issues := namespacesForCurrentSessionPermissions(session, options)
	rowsByKey := map[string]model.PermissionPath{}

	for _, namespace := range namespaces {
		review, err := session.client.AuthorizationV1().SelfSubjectRulesReviews().Create(
			session.ctx,
			&authv1.SelfSubjectRulesReview{
				Spec: authv1.SelfSubjectRulesReviewSpec{
					Namespace: namespace,
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			issues = append(issues, model.Issue{
				Kind:    "collection",
				Scope:   "permissions.authorization." + namespace,
				Message: "Current scope could not review effective namespace permissions directly from the authorization API.",
			})
			continue
		}
		if review.Status.Incomplete {
			issues = append(issues, model.Issue{
				Kind:    "collection",
				Scope:   "permissions.authorization." + namespace,
				Message: "Authorization review for this namespace was incomplete, so current-session capability rows may still be understated.",
			})
		}
		for _, row := range permissionRowsFromResourceRules(subject, currentIdentity.Confidence, namespace, review.Status.ResourceRules) {
			rowsByKey[row.Scope+"|"+row.ActionSummary] = row
		}
	}

	for _, row := range clusterPermissionRows(session, subject, currentIdentity.Confidence, &issues) {
		rowsByKey[row.Scope+"|"+row.ActionSummary] = row
	}

	rows := make([]model.PermissionPath, 0, len(rowsByKey))
	for _, row := range rowsByKey {
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if directPermissionPriorityOrder(rows[i].Priority) != directPermissionPriorityOrder(rows[j].Priority) {
			return directPermissionPriorityOrder(rows[i].Priority) < directPermissionPriorityOrder(rows[j].Priority)
		}
		if directPermissionScopeRank(rows[i].Scope) != directPermissionScopeRank(rows[j].Scope) {
			return directPermissionScopeRank(rows[i].Scope) > directPermissionScopeRank(rows[j].Scope)
		}
		return rows[i].ActionSummary < rows[j].ActionSummary
	})

	return rows, issues, nil
}

func (p liveProvider) resolveSession(options QueryOptions) (liveSession, error) {
	overrides := &clientcmd.ConfigOverrides{}
	if options.ContextName != "" {
		overrides.CurrentContext = options.ContextName
	}
	if options.Namespace != "" {
		overrides.Context.Namespace = options.Namespace
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(p.loadingRules, overrides)
	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return liveSession{}, fmt.Errorf("load kubeconfig: %w", err)
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return liveSession{}, fmt.Errorf("build kubernetes api config: %w", err)
	}
	restConfig.Timeout = apiTimeout

	namespace, _, err := clientConfig.Namespace()
	if err != nil || namespace == "" {
		namespace = defaultNamespace
	}

	client, err := kubernetes.NewForConfig(rest.CopyConfig(restConfig))
	if err != nil {
		return liveSession{}, fmt.Errorf("build kubernetes client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)

	return liveSession{
		client:             client,
		restConfig:         restConfig,
		rawConfig:          rawConfig,
		currentContextName: rawConfig.CurrentContext,
		effectiveNamespace: namespace,
		ctx:                ctx,
		cancel:             cancel,
	}, nil
}

func deriveCurrentIdentity(session liveSession, kubeconfigUser string) (model.CurrentIdentity, []string, []string) {
	if label, namespace, _, ok := parseServiceAccountSubject(tokenSubjectFromSession(session)); ok {
		evidence := []string{"Current bearer token exposes a service-account subject in the visible auth material."}
		return model.CurrentIdentity{
			Label:      label,
			Kind:       "ServiceAccount",
			Namespace:  &namespace,
			Confidence: "direct",
		}, evidence, []string{}
	}

	if label, namespace, _, ok := parseServiceAccountSubject(kubeconfigUser); ok {
		evidence := []string{"Current kubeconfig user name already looks like a service-account subject string."}
		return model.CurrentIdentity{
			Label:      label,
			Kind:       "ServiceAccount",
			Namespace:  &namespace,
			Confidence: "inferred",
		}, evidence, []string{"Current scope inferred the service account from kubeconfig naming, not a direct subject review response."}
	}

	return model.CurrentIdentity{
			Label:      "unknown current identity",
			Kind:       "Unknown",
			Confidence: "blocked",
		}, []string{}, []string{
			"Current kubeconfig and visible auth material do not directly expose the acting Kubernetes identity.",
		}
}

func tokenSubjectFromSession(session liveSession) string {
	token := strings.TrimSpace(session.restConfig.BearerToken)
	if token == "" && session.restConfig.BearerTokenFile != "" {
		bytes, err := os.ReadFile(session.restConfig.BearerTokenFile)
		if err == nil {
			token = strings.TrimSpace(string(bytes))
		}
	}
	if token == "" {
		return ""
	}

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ""
	}
	return payload.Subject
}

func parseServiceAccountSubject(subject string) (string, string, string, bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(subject, prefix) {
		return "", "", "", false
	}
	parts := strings.Split(subject, ":")
	if len(parts) != 4 {
		return "", "", "", false
	}
	return subject, parts[2], parts[3], true
}

func deriveSessionProfile(session liveSession, currentIdentity model.CurrentIdentity) model.SessionProfile {
	authMaterialType := "unknown"
	executionOrigin := "kubeconfig"

	contextRef := session.rawConfig.Contexts[session.currentContextName]
	if contextRef != nil {
		if authInfo, ok := session.rawConfig.AuthInfos[contextRef.AuthInfo]; ok && authInfo != nil {
			switch {
			case authInfo.Token != "" || authInfo.TokenFile != "":
				authMaterialType = "token"
			case authInfo.Exec != nil:
				authMaterialType = "exec plugin"
			case authInfo.ClientCertificate != "" || authInfo.ClientCertificateData != nil:
				authMaterialType = "client certificate"
			case authInfo.Username != "":
				authMaterialType = "basic auth"
			case authInfo.AuthProvider != nil:
				authMaterialType = "auth provider"
			}
		}
	}
	if strings.HasPrefix(session.restConfig.BearerTokenFile, serviceAccountTokenFilePrefix) {
		executionOrigin = "in-cluster"
	}

	footholdFamily := "unknown"
	if currentIdentity.Kind == "ServiceAccount" {
		footholdFamily = "service-account token"
	} else if authMaterialType != "unknown" {
		footholdFamily = "kubeconfig-backed session"
	}

	visibilityScope := "current api session"
	if session.effectiveNamespace != "" {
		visibilityScope = "namespace-defaulted api session"
	}

	return model.SessionProfile{
		AuthMaterialType: authMaterialType,
		ExecutionOrigin:  executionOrigin,
		FootholdFamily:   footholdFamily,
		VisibilityScope:  visibilityScope,
	}
}

func deriveLiveEnvironmentHint(server string, clusterName string) model.EnvironmentSummary {
	server = strings.ToLower(server)
	clusterName = strings.ToLower(clusterName)

	environmentType := "unknown"
	confidence := "heuristic"
	summary := "Current slice does not show strong enough provider markers to call this managed or self-managed with confidence."
	evidence := []string{"The visible API endpoint and cluster name do not carry a strong managed-cluster marker."}

	switch {
	case strings.Contains(server, ".azmk8s.io") || strings.Contains(server, ".eks.amazonaws.com") || strings.Contains(server, ".gke.") || strings.Contains(clusterName, "aks") || strings.Contains(clusterName, "eks") || strings.Contains(clusterName, "gke"):
		environmentType = "managed-like"
		summary = "Visible endpoint naming looks managed-service-shaped, so cloud-cluster bridge assumptions deserve attention."
		evidence = []string{"The visible endpoint or cluster name matches a common managed Kubernetes naming pattern."}
	case strings.Contains(server, "10.") || strings.Contains(server, "172.") || strings.Contains(server, "192.168.") || strings.HasPrefix(server, "https://127.") || strings.HasPrefix(server, "https://localhost"):
		environmentType = "self-managed-like"
		summary = "The visible API endpoint looks private or lab-shaped rather than strongly managed-service-branded."
		evidence = []string{"The visible API endpoint is an internal-style address without strong managed-cluster branding."}
	}

	return model.EnvironmentSummary{
		Type:       environmentType,
		Confidence: confidence,
		Summary:    summary,
		Evidence:   evidence,
	}
}

type liveWorkloadSnapshot struct {
	Workloads         []model.Workload
	Pods              []corev1.Pod
	PodWorkloadLabels map[string]string
	Issues            []model.Issue
}

func collectLiveWorkloadSnapshot(session liveSession, options QueryOptions) (liveWorkloadSnapshot, error) {
	pods, issues, err := listPodsWithFallback(session, options, "workloads.pods")
	if err != nil {
		return liveWorkloadSnapshot{}, err
	}

	deployments, deploymentIssues, err := listDeploymentsWithFallback(session, options, "workloads.deployments")
	if err != nil {
		return liveWorkloadSnapshot{}, err
	}
	issues = append(issues, deploymentIssues...)

	daemonSets, daemonSetIssues, err := listDaemonSetsWithFallback(session, options, "workloads.daemonsets")
	if err != nil {
		return liveWorkloadSnapshot{}, err
	}
	issues = append(issues, daemonSetIssues...)

	statefulSets, statefulSetIssues, err := listStatefulSetsWithFallback(session, options, "workloads.statefulsets")
	if err != nil {
		return liveWorkloadSnapshot{}, err
	}
	issues = append(issues, statefulSetIssues...)

	replicaSets, replicaSetIssues, err := listReplicaSetsWithFallback(session, options, "workloads.replicasets")
	if err != nil {
		return liveWorkloadSnapshot{}, err
	}
	issues = append(issues, replicaSetIssues...)

	workloads := make([]model.Workload, 0, len(pods)+len(deployments)+len(daemonSets)+len(statefulSets))
	podWorkloadLabels := map[string]string{}
	seen := map[string]struct{}{}
	visibleControllerLabels := map[string]string{}

	addWorkload := func(workload model.Workload) {
		label := workload.Namespace + "/" + workload.Name
		if _, ok := seen[label]; ok {
			return
		}
		seen[label] = struct{}{}
		workloads = append(workloads, workload)
	}

	for _, deployment := range deployments {
		workload := workloadFromTemplate(
			"Deployment",
			deployment.Namespace,
			deployment.Name,
			deployment.Spec.Template,
			int32PtrToInt(deployment.Spec.Replicas),
		)
		visibleControllerLabels[controllerMapKey("Deployment", deployment.Namespace, deployment.Name)] = workload.Namespace + "/" + workload.Name
		addWorkload(workload)
	}
	for _, daemonSet := range daemonSets {
		workload := workloadFromTemplate(
			"DaemonSet",
			daemonSet.Namespace,
			daemonSet.Name,
			daemonSet.Spec.Template,
			nil,
		)
		visibleControllerLabels[controllerMapKey("DaemonSet", daemonSet.Namespace, daemonSet.Name)] = workload.Namespace + "/" + workload.Name
		addWorkload(workload)
	}
	for _, statefulSet := range statefulSets {
		workload := workloadFromTemplate(
			"StatefulSet",
			statefulSet.Namespace,
			statefulSet.Name,
			statefulSet.Spec.Template,
			int32PtrToInt(statefulSet.Spec.Replicas),
		)
		visibleControllerLabels[controllerMapKey("StatefulSet", statefulSet.Namespace, statefulSet.Name)] = workload.Namespace + "/" + workload.Name
		addWorkload(workload)
	}

	replicaSetDeploymentLabels := map[string]string{}
	for _, replicaSet := range replicaSets {
		deploymentName, ok := ownerReferenceName(replicaSet.OwnerReferences, "Deployment")
		if !ok {
			continue
		}
		deploymentLabel := visibleControllerLabels[controllerMapKey("Deployment", replicaSet.Namespace, deploymentName)]
		if deploymentLabel == "" {
			continue
		}
		replicaSetDeploymentLabels[replicaSet.Namespace+"/"+replicaSet.Name] = deploymentLabel
	}

	for _, pod := range pods {
		label := controllerLabelForPod(pod, replicaSetDeploymentLabels, visibleControllerLabels)
		if label == "" {
			workload := workloadFromPod(pod)
			label = workload.Namespace + "/" + workload.Name
			addWorkload(workload)
		}
		podWorkloadLabels[pod.Namespace+"/"+pod.Name] = label
	}

	sort.SliceStable(workloads, func(i, j int) bool {
		if workloads[i].Namespace != workloads[j].Namespace {
			return workloads[i].Namespace < workloads[j].Namespace
		}
		return workloads[i].Name < workloads[j].Name
	})

	return liveWorkloadSnapshot{
		Workloads:         workloads,
		Pods:              pods,
		PodWorkloadLabels: podWorkloadLabels,
		Issues:            issues,
	}, nil
}

func workloadFromTemplate(kind string, namespace string, name string, template corev1.PodTemplateSpec, replicas *int) model.Workload {
	images := []string{}
	for _, container := range template.Spec.Containers {
		images = append(images, container.Image)
	}

	command := []string{}
	args := []string{}
	if len(template.Spec.Containers) > 0 {
		command = append(command, template.Spec.Containers[0].Command...)
		args = append(args, template.Spec.Containers[0].Args...)
	}

	envNames := []string{}
	envSeen := map[string]struct{}{}
	for _, container := range template.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == "" {
				continue
			}
			if _, ok := envSeen[env.Name]; ok {
				continue
			}
			envSeen[env.Name] = struct{}{}
			envNames = append(envNames, env.Name)
		}
	}
	sort.Strings(envNames)

	mountedSecretRefs, mountedConfigRefs, hostPathMounts, dockerSocketMount := podVolumeSignals(template.Spec.Volumes)
	addedCapabilities, privileged, allowPrivilegeEscalation, runsAsRoot := containerSecuritySignals(template.Spec)
	initContainers := containerNames(template.Spec.InitContainers)
	sidecars := []string{}
	if len(template.Spec.Containers) > 1 {
		sidecars = containerNames(template.Spec.Containers[1:])
	}

	var seccompProfile *string
	if template.Spec.SecurityContext != nil && template.Spec.SecurityContext.SeccompProfile != nil {
		value := string(template.Spec.SecurityContext.SeccompProfile.Type)
		seccompProfile = &value
	}

	return model.Workload{
		ID:                           strings.ToLower(kind) + ":" + namespace + ":" + name,
		Kind:                         kind,
		Name:                         name,
		Namespace:                    namespace,
		ServiceAccountName:           template.Spec.ServiceAccountName,
		Images:                       images,
		Command:                      command,
		Args:                         args,
		EnvNames:                     envNames,
		MountedSecretRefs:            mountedSecretRefs,
		MountedConfigRefs:            mountedConfigRefs,
		InitContainers:               initContainers,
		Sidecars:                     sidecars,
		Replicas:                     replicas,
		Privileged:                   privileged,
		AllowPrivilegeEscalation:     allowPrivilegeEscalation,
		RunsAsRoot:                   runsAsRoot,
		AddedCapabilities:            addedCapabilities,
		HostPathMounts:               hostPathMounts,
		DockerSocketMount:            dockerSocketMount,
		HostNetwork:                  template.Spec.HostNetwork,
		HostPID:                      template.Spec.HostPID,
		HostIPC:                      template.Spec.HostIPC,
		AutomountServiceAccountToken: template.Spec.AutomountServiceAccountToken,
		SeccompProfile:               seccompProfile,
	}
}

func workloadFromPod(pod corev1.Pod) model.Workload {
	return workloadFromTemplate(
		"Pod",
		pod.Namespace,
		pod.Name,
		corev1.PodTemplateSpec{Spec: pod.Spec},
		nil,
	)
}

func controllerLabelForPod(pod corev1.Pod, replicaSetDeploymentLabels map[string]string, visibleControllerLabels map[string]string) string {
	for _, owner := range pod.OwnerReferences {
		switch owner.Kind {
		case "StatefulSet", "DaemonSet":
			label := visibleControllerLabels[controllerMapKey(owner.Kind, pod.Namespace, owner.Name)]
			if label != "" {
				return label
			}
		case "ReplicaSet":
			label := replicaSetDeploymentLabels[pod.Namespace+"/"+owner.Name]
			if label != "" {
				return label
			}
		}
	}
	return ""
}

func controllerMapKey(kind string, namespace string, name string) string {
	return kind + ":" + namespace + ":" + name
}

func ownerReferenceName(owners []metav1.OwnerReference, kind string) (string, bool) {
	for _, owner := range owners {
		if owner.Kind == kind && owner.Name != "" {
			return owner.Name, true
		}
	}
	return "", false
}

func podVolumeSignals(volumes []corev1.Volume) ([]string, []string, []string, bool) {
	mountedSecretRefs := []string{}
	mountedConfigRefs := []string{}
	hostPathMounts := []string{}
	dockerSocketMount := false

	for _, volume := range volumes {
		switch {
		case volume.Secret != nil:
			mountedSecretRefs = append(mountedSecretRefs, volume.Secret.SecretName)
		case volume.ConfigMap != nil:
			mountedConfigRefs = append(mountedConfigRefs, volume.ConfigMap.Name)
		case volume.Projected != nil:
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					mountedSecretRefs = append(mountedSecretRefs, source.Secret.Name)
				}
				if source.ConfigMap != nil {
					mountedConfigRefs = append(mountedConfigRefs, source.ConfigMap.Name)
				}
			}
		case volume.HostPath != nil:
			hostPathMounts = append(hostPathMounts, volume.HostPath.Path)
			if strings.Contains(volume.HostPath.Path, "docker.sock") {
				dockerSocketMount = true
			}
		}
	}

	sort.Strings(mountedSecretRefs)
	sort.Strings(mountedConfigRefs)
	sort.Strings(hostPathMounts)
	return mountedSecretRefs, mountedConfigRefs, hostPathMounts, dockerSocketMount
}

func containerSecuritySignals(spec corev1.PodSpec) ([]string, bool, bool, bool) {
	addedCapabilities := []string{}
	capSeen := map[string]struct{}{}
	privileged := false
	allowPrivilegeEscalation := false
	runsAsRoot := false

	for _, container := range append([]corev1.Container{}, append(spec.InitContainers, spec.Containers...)...) {
		if container.SecurityContext == nil {
			continue
		}
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			privileged = true
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			allowPrivilegeEscalation = true
		}
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			runsAsRoot = true
		}
		if container.SecurityContext.Capabilities != nil {
			for _, capability := range container.SecurityContext.Capabilities.Add {
				name := string(capability)
				if _, ok := capSeen[name]; ok {
					continue
				}
				capSeen[name] = struct{}{}
				addedCapabilities = append(addedCapabilities, name)
			}
		}
	}

	sort.Strings(addedCapabilities)
	return addedCapabilities, privileged, allowPrivilegeEscalation, runsAsRoot
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, container := range containers {
		names = append(names, container.Name)
	}
	return names
}

func workloadsForService(service corev1.Service, pods []corev1.Pod, podWorkloadLabels map[string]string) []string {
	if len(service.Spec.Selector) == 0 {
		return []string{}
	}

	related := []string{}
	seen := map[string]struct{}{}
	for _, pod := range pods {
		if pod.Namespace != service.Namespace {
			continue
		}
		if !selectorMatchesLabels(service.Spec.Selector, pod.Labels) {
			continue
		}
		label := podWorkloadLabels[pod.Namespace+"/"+pod.Name]
		if label == "" {
			label = pod.Namespace + "/" + pod.Name
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		related = append(related, label)
	}
	sort.Strings(related)
	return related
}

func workloadsForIngress(ingress networkingv1.Ingress, serviceWorkloads map[string][]string) []string {
	workloads := []string{}
	seen := map[string]struct{}{}
	addServiceWorkloads := func(namespace string, serviceName string) {
		for _, workload := range serviceWorkloads[namespace+"/"+serviceName] {
			if _, ok := seen[workload]; ok {
				continue
			}
			seen[workload] = struct{}{}
			workloads = append(workloads, workload)
		}
	}

	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		addServiceWorkloads(ingress.Namespace, ingress.Spec.DefaultBackend.Service.Name)
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			addServiceWorkloads(ingress.Namespace, path.Backend.Service.Name)
		}
	}
	sort.Strings(workloads)
	return workloads
}

func selectorMatchesLabels(selector map[string]string, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func serviceExposureType(service corev1.Service) string {
	switch service.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		return "LoadBalancer"
	case corev1.ServiceTypeNodePort:
		return "NodePort"
	default:
		return "Service"
	}
}

func serviceLooksPublic(service corev1.Service) bool {
	return service.Spec.Type == corev1.ServiceTypeLoadBalancer || service.Spec.Type == corev1.ServiceTypeNodePort
}

func serviceExternalTargets(service corev1.Service) []string {
	targets := []string{}
	switch service.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				targets = append(targets, ingress.IP)
			}
			if ingress.Hostname != "" {
				targets = append(targets, ingress.Hostname)
			}
		}
	case corev1.ServiceTypeNodePort:
		for _, port := range service.Spec.Ports {
			if port.NodePort != 0 {
				targets = append(targets, fmt.Sprintf("nodePort:%d", port.NodePort))
			}
		}
	}
	if len(targets) == 0 && service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		targets = append(targets, "pending load balancer address")
	}
	sort.Strings(targets)
	return targets
}

func ingressExternalTargets(ingress networkingv1.Ingress) []string {
	targets := []string{}
	for _, rule := range ingress.Spec.Rules {
		if rule.Host != "" {
			targets = append(targets, rule.Host)
		}
	}
	for _, item := range ingress.Status.LoadBalancer.Ingress {
		if item.IP != "" {
			targets = append(targets, item.IP)
		}
		if item.Hostname != "" {
			targets = append(targets, item.Hostname)
		}
	}
	sort.Strings(targets)
	return targets
}

func rawRoleBindingFromLive(binding rbacv1.RoleBinding) rawRoleBinding {
	return rawRoleBinding{
		Name:      binding.Name,
		Namespace: binding.Namespace,
		RoleRef: rawRoleRef{
			Kind: binding.RoleRef.Kind,
			Name: binding.RoleRef.Name,
		},
		Subjects: rawSubjectsFromLive(binding.Subjects),
	}
}

func rawClusterRoleBindingFromLive(binding rbacv1.ClusterRoleBinding) rawRoleBinding {
	return rawRoleBinding{
		Name: binding.Name,
		RoleRef: rawRoleRef{
			Kind: binding.RoleRef.Kind,
			Name: binding.RoleRef.Name,
		},
		Subjects: rawSubjectsFromLive(binding.Subjects),
	}
}

func rawSubjectsFromLive(subjects []rbacv1.Subject) []rawSubject {
	rows := make([]rawSubject, 0, len(subjects))
	for _, subject := range subjects {
		rows = append(rows, rawSubject{
			Kind:      subject.Kind,
			Name:      subject.Name,
			Namespace: subject.Namespace,
		})
	}
	return rows
}

func rawRoleFromRole(role rbacv1.Role) rawRole {
	return rawRole{
		Name:         role.Name,
		Namespace:    role.Namespace,
		RulesVisible: boolPtr(true),
		Rules:        rawRulesFromLive(role.Rules),
	}
}

func rawRoleFromClusterRole(role rbacv1.ClusterRole) rawRole {
	return rawRole{
		Name:         role.Name,
		RulesVisible: boolPtr(true),
		Rules:        rawRulesFromLive(role.Rules),
	}
}

func rawRulesFromLive(rules []rbacv1.PolicyRule) []rawPolicyRule {
	rows := make([]rawPolicyRule, 0, len(rules))
	for _, rule := range rules {
		rows = append(rows, rawPolicyRule{
			Verbs:     append([]string{}, rule.Verbs...),
			Resources: append([]string{}, rule.Resources...),
			APIGroups: append([]string{}, rule.APIGroups...),
		})
	}
	return rows
}

func listPodsWithFallback(session liveSession, options QueryOptions, scope string) ([]corev1.Pod, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "pods", func(ctx context.Context, namespace string) ([]corev1.Pod, error) {
		list, err := session.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listDeploymentsWithFallback(session liveSession, options QueryOptions, scope string) ([]appsv1.Deployment, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "deployments", func(ctx context.Context, namespace string) ([]appsv1.Deployment, error) {
		list, err := session.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listDaemonSetsWithFallback(session liveSession, options QueryOptions, scope string) ([]appsv1.DaemonSet, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "daemonsets", func(ctx context.Context, namespace string) ([]appsv1.DaemonSet, error) {
		list, err := session.client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listStatefulSetsWithFallback(session liveSession, options QueryOptions, scope string) ([]appsv1.StatefulSet, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "statefulsets", func(ctx context.Context, namespace string) ([]appsv1.StatefulSet, error) {
		list, err := session.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listReplicaSetsWithFallback(session liveSession, options QueryOptions, scope string) ([]appsv1.ReplicaSet, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "replicasets", func(ctx context.Context, namespace string) ([]appsv1.ReplicaSet, error) {
		list, err := session.client.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listServiceAccountsWithFallback(session liveSession, options QueryOptions, scope string) ([]corev1.ServiceAccount, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "service accounts", func(ctx context.Context, namespace string) ([]corev1.ServiceAccount, error) {
		list, err := session.client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listServicesWithFallback(session liveSession, options QueryOptions) ([]corev1.Service, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, "exposure.services", "services", func(ctx context.Context, namespace string) ([]corev1.Service, error) {
		list, err := session.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listIngressesWithFallback(session liveSession, options QueryOptions) ([]networkingv1.Ingress, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, "exposure.ingresses", "ingresses", func(ctx context.Context, namespace string) ([]networkingv1.Ingress, error) {
		list, err := session.client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listRoleBindingsWithFallback(session liveSession, options QueryOptions, scope string) ([]rbacv1.RoleBinding, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "role bindings", func(ctx context.Context, namespace string) ([]rbacv1.RoleBinding, error) {
		list, err := session.client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listRolesWithFallback(session liveSession, options QueryOptions, scope string) ([]rbacv1.Role, []model.Issue, error) {
	return listWithNamespaceFallback(session, options, scope, "roles", func(ctx context.Context, namespace string) ([]rbacv1.Role, error) {
		list, err := session.client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	})
}

func listWithNamespaceFallback[T any](
	session liveSession,
	options QueryOptions,
	scope string,
	resourceLabel string,
	listFn func(context.Context, string) ([]T, error),
) ([]T, []model.Issue, error) {
	if err := liveSessionContextErr(session); err != nil {
		return nil, nil, err
	}
	ctx := liveSessionContext(session)
	if options.Namespace != "" {
		items, err := listFn(ctx, options.Namespace)
		if err != nil {
			return nil, nil, fmt.Errorf("list %s in namespace %s: %w", resourceLabel, options.Namespace, err)
		}
		return items, nil, nil
	}

	items, err := listFn(ctx, metav1.NamespaceAll)
	if err == nil {
		return items, nil, nil
	}

	fallbackItems, fallbackErr := listFn(ctx, session.effectiveNamespace)
	if fallbackErr != nil {
		return nil, nil, fmt.Errorf("list %s from api: %w", resourceLabel, err)
	}
	return fallbackItems, []model.Issue{namespaceFallbackIssue(scope, session.effectiveNamespace)}, nil
}

func liveSessionContext(session liveSession) context.Context {
	if session.ctx != nil {
		return session.ctx
	}
	return context.Background()
}

func liveSessionContextErr(session liveSession) error {
	if session.ctx == nil {
		return nil
	}
	return session.ctx.Err()
}

func namespaceFallbackIssue(scope string, namespace string) model.Issue {
	return model.Issue{
		Kind:    "collection",
		Scope:   scope,
		Message: fmt.Sprintf("Current scope could not list across all namespaces, so this read fell back to namespace %s only.", namespace),
	}
}

func secretRefNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Name != "" {
			names = append(names, ref.Name)
		}
	}
	sort.Strings(names)
	return names
}

func secretObjectRefNames(refs []corev1.ObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Name != "" {
			names = append(names, ref.Name)
		}
	}
	sort.Strings(names)
	return names
}

func boolPtr(value bool) *bool {
	return &value
}

func int32PtrToInt(value *int32) *int {
	if value == nil {
		return nil
	}
	converted := int(*value)
	return &converted
}

func namespacesForCurrentSessionPermissions(session liveSession, options QueryOptions) ([]string, []model.Issue) {
	if options.Namespace != "" {
		return []string{options.Namespace}, nil
	}

	list, err := session.client.CoreV1().Namespaces().List(session.ctx, metav1.ListOptions{})
	if err != nil {
		return []string{session.effectiveNamespace}, []model.Issue{{
			Kind:    "collection",
			Scope:   "permissions.authorization",
			Message: fmt.Sprintf("Current scope could not list visible namespaces, so direct authorization review fell back to namespace %s only.", session.effectiveNamespace),
		}}
	}

	namespaces := make([]string, 0, len(list.Items))
	for _, namespace := range list.Items {
		namespaces = append(namespaces, namespace.Name)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

func permissionRowsFromResourceRules(subject string, subjectConfidence string, namespace string, rules []authv1.ResourceRule) []model.PermissionPath {
	scope := "namespace/" + namespace
	rows := []model.PermissionPath{}

	add := func(actionSummary string, actionVerb string, targetGroup string, targetResources []string, baseScore int, nextReview string, whyCare string) {
		rows = append(rows, model.PermissionPath{
			ID:                "current-session:" + namespace + ":" + strings.ReplaceAll(actionSummary, " ", "-"),
			Subject:           subject,
			SubjectConfidence: subjectConfidence,
			Scope:             scope,
			ActionVerb:        actionVerb,
			TargetGroup:       targetGroup,
			TargetResources:   targetResources,
			ActionSummary:     actionSummary,
			EvidenceStatus:    "direct",
			EvidenceSource:    "authorization API",
			RelatedBindings:   []string{},
			Priority:          directPermissionPriority(baseScore),
			WhyCare:           whyCare,
			NextReview:        nextReview,
		})
	}

	if resourceRulesAllow(rules, []string{"get", "list", "watch"}, []string{""}, []string{"secrets"}) {
		add(
			"can read secrets",
			"get",
			"",
			nil,
			25,
			"secrets",
			fmt.Sprintf("Current session can read secrets in %s directly from the authorization API, which makes secret-path review immediate.", scope),
		)
	}
	if resourceRulesAllow(rules, []string{"create"}, []string{""}, []string{"pods/exec"}) {
		add(
			"can exec into pods",
			"create",
			"pods",
			[]string{"pods/exec"},
			35,
			"workloads",
			fmt.Sprintf("Current session can open pod exec in %s directly from the authorization API, which creates an immediate workload control lead.", scope),
		)
	}
	if resourceRulesAllow(rules, []string{"create"}, []string{""}, []string{"pods"}) {
		add("can create pods", "create", "pods", []string{"pods"}, 35, "workloads", fmt.Sprintf("Current session can create pods in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"patch"}, []string{""}, []string{"pods"}) {
		add("can patch pods", "patch", "pods", []string{"pods"}, 31, "workloads", fmt.Sprintf("Current session can patch pods in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"update"}, []string{""}, []string{"pods"}) {
		add("can update pods", "update", "pods", []string{"pods"}, 30, "workloads", fmt.Sprintf("Current session can update pods in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"delete"}, []string{""}, []string{"pods"}) {
		add("can delete pods", "delete", "pods", []string{"pods"}, 29, "workloads", fmt.Sprintf("Current session can delete pods in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"create"}, []string{"apps", "batch"}, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) {
		add("can create workload controllers", "create", "workload-controllers", []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets"}, 32, "workloads", fmt.Sprintf("Current session can create workload controllers in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"patch"}, []string{"apps", "batch"}, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) {
		add("can patch workload controllers", "patch", "workload-controllers", []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets"}, 34, "workloads", fmt.Sprintf("Current session can patch workload controllers in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"update"}, []string{"apps", "batch"}, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) {
		add("can update workload controllers", "update", "workload-controllers", []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets"}, 33, "workloads", fmt.Sprintf("Current session can update workload controllers in %s directly from the authorization API.", scope))
	}
	if resourceRulesAllow(rules, []string{"delete"}, []string{"apps", "batch"}, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) {
		add("can delete workload controllers", "delete", "workload-controllers", []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets"}, 29, "workloads", fmt.Sprintf("Current session can delete workload controllers in %s directly from the authorization API.", scope))
	}

	return rows
}

func clusterPermissionRows(session liveSession, subject string, subjectConfidence string, issues *[]model.Issue) []model.PermissionPath {
	rows := []model.PermissionPath{}
	checks := []struct {
		actionSummary string
		resource      string
		group         string
		verb          string
		nextReview    string
		score         int
	}{
		{actionSummary: "can impersonate serviceaccounts", resource: "serviceaccounts", verb: "impersonate", nextReview: "rbac", score: 50},
		{actionSummary: "can impersonate users", resource: "users", verb: "impersonate", nextReview: "rbac", score: 50},
		{actionSummary: "can impersonate groups", resource: "groups", verb: "impersonate", nextReview: "rbac", score: 50},
		{actionSummary: "can bind roles", resource: "roles", group: "rbac.authorization.k8s.io", verb: "bind", nextReview: "rbac", score: 45},
		{actionSummary: "can escalate roles", resource: "roles", group: "rbac.authorization.k8s.io", verb: "escalate", nextReview: "rbac", score: 45},
		{actionSummary: "can touch nodes", resource: "nodes", verb: "get", nextReview: "workloads", score: 40},
		{actionSummary: "can change admission or policy", resource: "mutatingwebhookconfigurations", group: "admissionregistration.k8s.io", verb: "patch", nextReview: "rbac", score: 30},
	}

	for _, check := range checks {
		allowed, err := selfSubjectAccessAllowed(session, authv1.ResourceAttributes{
			Group:    check.group,
			Resource: check.resource,
			Verb:     check.verb,
		})
		if err != nil {
			*issues = append(*issues, model.Issue{
				Kind:    "collection",
				Scope:   "permissions.authorization.cluster",
				Message: "Current scope could not confirm some cluster-scoped capabilities directly from the authorization API.",
			})
			continue
		}
		if !allowed {
			continue
		}
		rows = append(rows, model.PermissionPath{
			ID:                "current-session:cluster:" + strings.ReplaceAll(check.actionSummary, " ", "-"),
			Subject:           subject,
			SubjectConfidence: subjectConfidence,
			Scope:             "cluster-wide",
			ActionVerb:        clusterPermissionActionVerb(check.actionSummary),
			ActionSummary:     check.actionSummary,
			EvidenceStatus:    "direct",
			EvidenceSource:    "authorization API",
			RelatedBindings:   []string{},
			Priority:          directPermissionPriority(check.score),
			WhyCare:           fmt.Sprintf("Current session can %s directly from the authorization API.", strings.TrimPrefix(check.actionSummary, "can ")),
			NextReview:        check.nextReview,
		})
	}

	return rows
}

func selfSubjectAccessAllowed(session liveSession, attributes authv1.ResourceAttributes) (bool, error) {
	review, err := session.client.AuthorizationV1().SelfSubjectAccessReviews().Create(
		session.ctx,
		&authv1.SelfSubjectAccessReview{
			Spec: authv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &attributes,
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return false, err
	}
	return review.Status.Allowed, nil
}

func resourceRulesAllow(rules []authv1.ResourceRule, verbs []string, groups []string, resources []string) bool {
	for _, rule := range rules {
		if !stringSliceAllows(rule.Verbs, verbs) {
			continue
		}
		if !stringSliceAllows(rule.APIGroups, groups) {
			continue
		}
		if !stringSliceAllows(rule.Resources, resources) {
			continue
		}
		return true
	}
	return false
}

func stringSliceAllows(available []string, wanted []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, availableValue := range available {
		if availableValue == "*" {
			return true
		}
		for _, wantedValue := range wanted {
			if availableValue == wantedValue {
				return true
			}
		}
	}
	return false
}

func directPermissionPriority(score int) string {
	switch {
	case score >= 45:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func directPermissionPriorityOrder(priority string) int {
	switch priority {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func directPermissionScopeRank(scope string) int {
	if scope == "cluster-wide" {
		return 2
	}
	if strings.HasPrefix(scope, "namespace/") {
		return 1
	}
	return 0
}

func clusterPermissionActionVerb(actionSummary string) string {
	if strings.HasPrefix(actionSummary, "can ") {
		parts := strings.Fields(strings.TrimPrefix(actionSummary, "can "))
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}
