package selector

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

func newClient(objs ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func ns(name string, labels map[string]string) *corev1.Namespace {
	if labels == nil {
		labels = map[string]string{}
	}
	if _, ok := labels[NamespaceMetadataNameLabel]; !ok {
		labels[NamespaceMetadataNameLabel] = name
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func pod(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels}}
}

func TestMatchesNilSelectorMatchesEverything(t *testing.T) {
	c := newClient()
	spec := v1alpha1.AegisPolicySpec{Mode: "audit"}
	got, err := Matches(context.Background(), c, spec, Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("nil selector should match everything")
	}
}

func TestMatchesWorkloadSelectorMatchExpressions(t *testing.T) {
	c := newClient(
		ns("default", nil),
		pod("default", "frontend", map[string]string{"app": "web", "tier": "frontend"}),
		pod("default", "db", map[string]string{"app": "web", "tier": "backend"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend"}},
				},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{Namespace: "default"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected to match the frontend pod via matchExpressions")
	}
}

func TestMatchesWorkloadSelectorNoMatchingPods(t *testing.T) {
	c := newClient(
		ns("default", nil),
		pod("default", "db", map[string]string{"tier": "backend"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "frontend"},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{Namespace: "default"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("expected no match when no pod carries the requested label")
	}
}

func TestMatchesWorkloadSelectorMatchNamespaceNames(t *testing.T) {
	c := newClient(
		ns("kube-system", nil),
		ns("prod", nil),
		pod("prod", "api", map[string]string{"app": "api"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			MatchNamespaceNames: []string{"prod"},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "api"},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected match for matchNamespaceNames=prod with matching pod")
	}
}

func TestMatchesWorkloadSelectorNamespaceSelectorMatchExpressions(t *testing.T) {
	c := newClient(
		ns("prod", map[string]string{"env": "prod"}),
		ns("dev", map[string]string{"env": "dev"}),
		pod("prod", "api", map[string]string{"app": "api"}),
		pod("dev", "api", map[string]string{"app": "api"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "api"},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected match via namespaceSelector")
	}
}

func TestMatchesWorkloadSelectorPrefersOverLegacySelector(t *testing.T) {
	c := newClient(
		ns("default", nil),
		pod("default", "frontend", map[string]string{"app": "web"}),
	)
	// Legacy selector targets "nope" which has no pods. WorkloadSelector
	// targets "web" which has a pod. WorkloadSelector should win.
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		Selector: &v1alpha1.PolicySelector{
			MatchLabels: map[string]string{"app": "nope"},
		},
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{Namespace: "default"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("WorkloadSelector should take precedence over legacy Selector")
	}
}

func TestMatchesLegacySelectorBackCompat(t *testing.T) {
	c := newClient(
		ns("default", nil),
		pod("default", "web", map[string]string{"app": "web"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		Selector: &v1alpha1.PolicySelector{
			MatchLabels: map[string]string{"app": "web"},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{Namespace: "default"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("legacy selector should still work for backwards compatibility")
	}
}

func TestMatchesNamespaceScopeIgnoresOtherNamespaces(t *testing.T) {
	c := newClient(
		ns("default", nil),
		ns("other", nil),
		pod("other", "web", map[string]string{"app": "web"}),
	)
	spec := v1alpha1.AegisPolicySpec{
		Mode: "enforce",
		WorkloadSelector: &v1alpha1.WorkloadSelector{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
		},
	}
	got, err := Matches(context.Background(), c, spec, Scope{Namespace: "default"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Error("namespaced scope should not see pods in other namespaces")
	}
}
