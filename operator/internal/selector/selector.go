// Package selector evaluates AegisPolicy workload selectors against the
// live cluster state. It is the single place that knows how to interpret
// both the legacy `spec.selector` (PolicySelector) and the new
// `spec.workloadSelector` (WorkloadSelector with full LabelSelector
// matchExpressions support).
//
// For v0.5.0 the selector is evaluated at "does any matching workload
// exist in the cluster?" granularity, which is what the merged-policy
// reconciler needs to decide whether a given policy contributes to the
// node-wide ConfigMap. Per-pod ConfigMap sharding is v0.6.0 work.
package selector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// NamespaceMetadataNameLabel is the well-known label every namespace
// carries (added automatically by the kube-apiserver since 1.21).
// matchNamespaceNames lowers to a matchExpressions clause on this label.
const NamespaceMetadataNameLabel = "kubernetes.io/metadata.name"

// Scope describes the scope a selector is evaluated against.
//
//   - For an AegisPolicy, ScopeNamespace is the policy's own namespace and
//     the selector must not reach outside it (the webhook rejects that).
//   - For an AegisClusterPolicy, ScopeNamespace is empty and the selector
//     ranges over the entire cluster.
type Scope struct {
	// Namespace, when non-empty, restricts the selector to a single
	// namespace. Cluster-scoped callers pass an empty string.
	Namespace string
}

// Matches reports whether at least one workload in the cluster satisfies
// the policy's selector. A nil/empty selector matches everything in
// scope. The function falls back to the legacy `spec.selector` only when
// `spec.workloadSelector` is unset, mirroring the documented precedence.
//
// Errors from the API server are returned to the caller; an empty pod
// list is reported as "no match" (false, nil).
func Matches(ctx context.Context, c client.Reader, spec v1alpha1.AegisPolicySpec, scope Scope) (bool, error) {
	if spec.WorkloadSelector != nil {
		return matchesWorkloadSelector(ctx, c, spec.WorkloadSelector, scope)
	}
	if spec.Selector != nil {
		return matchesLegacySelector(ctx, c, spec.Selector, scope)
	}
	// No selector at all → applies to everything in scope.
	return true, nil
}

func matchesWorkloadSelector(ctx context.Context, c client.Reader, ws *v1alpha1.WorkloadSelector, scope Scope) (bool, error) {
	// Resolve namespace set first, then check pods inside it.
	namespaces, err := resolveNamespaces(ctx, c, ws, scope)
	if err != nil {
		return false, fmt.Errorf("resolving namespaces: %w", err)
	}
	if len(namespaces) == 0 {
		// Selector pinned to namespaces that don't exist (yet) — no match.
		// We don't treat this as an error because namespaces come and go
		// independently of policies.
		return false, nil
	}

	podSelector, err := buildLabelSelector(ws.PodSelector)
	if err != nil {
		return false, fmt.Errorf("building pod selector: %w", err)
	}

	listOpts := []client.ListOption{client.MatchingLabelsSelector{Selector: podSelector}}
	for _, ns := range namespaces {
		opts := append([]client.ListOption{client.InNamespace(ns)}, listOpts...)
		var pods corev1.PodList
		if err := c.List(ctx, &pods, opts...); err != nil {
			return false, fmt.Errorf("listing pods in %q: %w", ns, err)
		}
		if len(pods.Items) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// resolveNamespaces returns the concrete namespace names a WorkloadSelector
// applies to, taking the scope and the various selector fields into account.
//
// Precedence:
//   1. If scope.Namespace is set (namespaced policy), the result is always
//      exactly that namespace; cross-namespace selection is forbidden.
//   2. If matchNamespaceNames is non-empty, return its (deduplicated) values.
//   3. If namespaceSelector is non-empty, list namespaces that match it.
//   4. Otherwise, return all namespaces in the cluster.
func resolveNamespaces(ctx context.Context, c client.Reader, ws *v1alpha1.WorkloadSelector, scope Scope) ([]string, error) {
	if scope.Namespace != "" {
		return []string{scope.Namespace}, nil
	}

	if len(ws.MatchNamespaceNames) > 0 {
		seen := make(map[string]struct{}, len(ws.MatchNamespaceNames))
		out := make([]string, 0, len(ws.MatchNamespaceNames))
		for _, n := range ws.MatchNamespaceNames {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
		return out, nil
	}

	nsSelector, err := buildLabelSelector(ws.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("building namespace selector: %w", err)
	}

	var namespaces corev1.NamespaceList
	if err := c.List(ctx, &namespaces, client.MatchingLabelsSelector{Selector: nsSelector}); err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	out := make([]string, 0, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		out = append(out, ns.Name)
	}
	return out, nil
}

// buildLabelSelector turns a *metav1.LabelSelector into a labels.Selector,
// returning labels.Everything() for nil — which is the documented "match
// everything" behaviour for both pod and namespace selectors.
func buildLabelSelector(ls *metav1.LabelSelector) (labels.Selector, error) {
	if ls == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(ls)
}

// matchesLegacySelector preserves the v0.4.x semantics of the deprecated
// `spec.selector` field. Kept verbatim so policies that haven't migrated
// to workloadSelector continue to behave the same way.
func matchesLegacySelector(ctx context.Context, c client.Reader, sel *v1alpha1.PolicySelector, scope Scope) (bool, error) {
	if scope.Namespace != "" {
		// For namespaced policies the legacy selector is checked inside
		// the policy's own namespace only. matchNamespaces is ignored
		// to avoid surprising cross-namespace behaviour from the new
		// reconciler; the webhook also rejects this for new policies.
		if len(sel.MatchLabels) == 0 {
			return true, nil
		}
		var pods corev1.PodList
		if err := c.List(ctx, &pods,
			client.InNamespace(scope.Namespace),
			client.MatchingLabels(sel.MatchLabels)); err != nil {
			return false, fmt.Errorf("listing pods: %w", err)
		}
		return len(pods.Items) > 0, nil
	}

	// Cluster scope.
	if len(sel.MatchNamespaces) > 0 {
		for _, ns := range sel.MatchNamespaces {
			var namespace corev1.Namespace
			if err := c.Get(ctx, client.ObjectKey{Name: ns}, &namespace); err == nil {
				return true, nil
			}
		}
		return false, nil
	}
	if len(sel.MatchLabels) > 0 {
		var pods corev1.PodList
		if err := c.List(ctx, &pods, client.MatchingLabels(sel.MatchLabels)); err != nil {
			return false, fmt.Errorf("listing pods: %w", err)
		}
		return len(pods.Items) > 0, nil
	}
	return true, nil
}
