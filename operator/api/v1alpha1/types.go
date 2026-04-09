package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ap,categories=aegisbpf
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="EnforceCapable",type=string,JSONPath=`.status.conditions[?(@.type=="EnforceCapable")].status`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.appliedNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AegisPolicy defines a namespaced security policy enforced by Aegis-BPF.
type AegisPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AegisPolicySpec   `json:"spec,omitempty"`
	Status AegisPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AegisPolicyList contains a list of AegisPolicy resources.
type AegisPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AegisPolicy `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=acp,categories=aegisbpf
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="EnforceCapable",type=string,JSONPath=`.status.conditions[?(@.type=="EnforceCapable")].status`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AegisClusterPolicy defines a cluster-wide security policy enforced by Aegis-BPF.
type AegisClusterPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AegisPolicySpec   `json:"spec,omitempty"`
	Status AegisPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AegisClusterPolicyList contains a list of AegisClusterPolicy resources.
type AegisClusterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AegisClusterPolicy `json:"items"`
}

// AegisPolicySpec defines the desired state of an Aegis security policy.
type AegisPolicySpec struct {
	// Mode controls whether the policy enforces or audits.
	// +kubebuilder:validation:Enum=enforce;audit
	// +kubebuilder:default=audit
	Mode string `json:"mode"`

	// Selector restricts which workloads this policy applies to.
	//
	// Deprecated: use WorkloadSelector instead. If both Selector and
	// WorkloadSelector are set, WorkloadSelector takes precedence and a
	// Deprecated condition is recorded on the policy status.
	// +optional
	Selector *PolicySelector `json:"selector,omitempty"`

	// WorkloadSelector selects the workloads this policy applies to using
	// the expressive Kubernetes LabelSelector model (matchLabels +
	// matchExpressions), plus a separate namespace selector. Replaces the
	// legacy `selector` field; if both are set, WorkloadSelector wins.
	// +optional
	WorkloadSelector *WorkloadSelector `json:"workloadSelector,omitempty"`

	// FileRules defines file access deny and protect rules.
	// +optional
	FileRules *FileRules `json:"fileRules,omitempty"`

	// NetworkRules defines network deny rules.
	// +optional
	NetworkRules *NetworkRules `json:"networkRules,omitempty"`

	// ExecRules defines execution allow/deny rules.
	// +optional
	ExecRules *ExecRules `json:"execRules,omitempty"`

	// KernelRules defines kernel-level protection rules.
	// +optional
	KernelRules *KernelRules `json:"kernelRules,omitempty"`
}

// PolicySelector restricts which workloads a policy applies to.
//
// Deprecated: use WorkloadSelector instead. This struct is retained so
// existing v1alpha1 YAMLs continue to parse, but new policies should use
// WorkloadSelector which supports LabelSelector matchExpressions.
type PolicySelector struct {
	// MatchLabels selects pods by label.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchNamespaces restricts the policy to specific namespaces.
	// +optional
	MatchNamespaces []string `json:"matchNamespaces,omitempty"`
}

// WorkloadSelector selects the pods a policy applies to using the
// standard Kubernetes LabelSelector model. All fields are AND-ed. A nil
// or empty WorkloadSelector matches everything in the policy's scope
// (the policy's own namespace for AegisPolicy, or cluster-wide for
// AegisClusterPolicy).
//
// For namespaced AegisPolicy resources, NamespaceSelector and
// MatchNamespaceNames must be empty or reference only the policy's own
// namespace; cross-namespace selection from a namespaced policy is
// rejected by the admission webhook.
type WorkloadSelector struct {
	// PodSelector selects pods within the matched namespaces. Supports
	// both matchLabels and matchExpressions (In, NotIn, Exists,
	// DoesNotExist), mirroring Kubernetes NetworkPolicy semantics.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector restricts which namespaces the PodSelector runs
	// against. An empty NamespaceSelector matches all namespaces (subject
	// to the CRD scope — namespaced AegisPolicy is always limited to its
	// own namespace). Supports matchLabels and matchExpressions.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// MatchNamespaceNames is a convenience shortcut equivalent to a
	// NamespaceSelector with matchExpressions:
	//   kubernetes.io/metadata.name In [<names>]
	// Kept because every competing project ships a by-name namespace
	// selector and users expect it.
	// +optional
	MatchNamespaceNames []string `json:"matchNamespaceNames,omitempty"`
}

// RuleAction is the per-rule enforcement action.
//
// Allow and Block are supported in v0.5.0. Audit is reserved for a future
// release and is rejected by the admission webhook today, because the
// daemon's INI format encodes action in section names (`[deny_*]` vs
// `[allow_*]`) and mode is policy-wide; per-rule audit requires a daemon
// change that is deliberately out of scope for this release.
//
// +kubebuilder:validation:Enum=Allow;Block
type RuleAction string

const (
	// RuleActionAllow explicitly permits a rule's target. Within the
	// merged cluster policy, Allow takes precedence over Block for the
	// same literal target (documented in docs/POLICY_SEMANTICS.md).
	RuleActionAllow RuleAction = "Allow"

	// RuleActionBlock denies the rule's target. This is the default when
	// `action` is unset on a rule.
	RuleActionBlock RuleAction = "Block"
)

// FileRules defines file access control rules.
type FileRules struct {
	// Deny lists files to block access to.
	// +optional
	Deny []FileRule `json:"deny,omitempty"`

	// Protect lists files to monitor for integrity changes.
	// +optional
	Protect []FileRule `json:"protect,omitempty"`
}

// FileRule identifies a file by path or inode.
type FileRule struct {
	// Action is the enforcement action for this rule. Defaults to Block
	// if unset, which preserves backwards compatibility with v0.4.x
	// policies that had no per-rule action field.
	//
	// Inode-based targets only support Action=Block today (the daemon
	// has no [allow_inode] section). The webhook rejects Action=Allow
	// with a non-empty Inode.
	// +kubebuilder:default=Block
	// +optional
	Action RuleAction `json:"action,omitempty"`

	// Path is the file path to match.
	// +optional
	Path string `json:"path,omitempty"`

	// Inode is the device:inode pair (e.g., "259:12345").
	// +kubebuilder:validation:Pattern=`^\d+:\d+$`
	// +optional
	Inode string `json:"inode,omitempty"`
}

// NetworkRules defines network access control rules.
type NetworkRules struct {
	// Deny lists network destinations to block.
	// +optional
	Deny []NetworkRule `json:"deny,omitempty"`
}

// NetworkRule identifies a network destination to control.
type NetworkRule struct {
	// Action is the enforcement action for this rule. Defaults to Block
	// if unset. Allow rules take precedence over Block rules for the
	// same literal target when multiple policies are merged.
	// +kubebuilder:default=Block
	// +optional
	Action RuleAction `json:"action,omitempty"`

	// IP is an exact IP address to match.
	// +optional
	IP string `json:"ip,omitempty"`

	// CIDR is a CIDR range to deny (e.g., "10.0.0.0/8").
	// +optional
	CIDR string `json:"cidr,omitempty"`

	// Port is the destination port to deny (1-65535).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int `json:"port,omitempty"`

	// Protocol is the transport protocol ("tcp" or "udp").
	// +kubebuilder:validation:Enum=tcp;udp
	// +optional
	Protocol string `json:"protocol,omitempty"`

	// Direction is the traffic direction ("outbound" or "inbound").
	// +kubebuilder:validation:Enum=outbound;inbound
	// +optional
	Direction string `json:"direction,omitempty"`
}

// ExecRules defines execution control rules.
type ExecRules struct {
	// AllowBinaryHashes lists SHA-256 hashes of allowed binaries.
	// +optional
	AllowBinaryHashes []string `json:"allowBinaryHashes,omitempty"`

	// DenyBinaryHashes lists SHA-256 hashes of denied binaries.
	// +optional
	DenyBinaryHashes []string `json:"denyBinaryHashes,omitempty"`

	// DenyComm lists process command names to deny execution.
	// +optional
	DenyComm []string `json:"denyComm,omitempty"`
}

// KernelRules defines kernel-level protection mechanisms.
type KernelRules struct {
	// BlockModuleLoad prevents loading of kernel modules.
	// +optional
	BlockModuleLoad bool `json:"blockModuleLoad,omitempty"`

	// BlockPtrace prevents ptrace-based process debugging/injection.
	// +optional
	BlockPtrace bool `json:"blockPtrace,omitempty"`

	// BlockBpfSyscall prevents unauthorized BPF program loading.
	// +optional
	BlockBpfSyscall bool `json:"blockBpfSyscall,omitempty"`
}

// Standard condition types for AegisPolicy and AegisClusterPolicy.
//
// Operators should consume these instead of the legacy `Phase` field, which
// remains for backwards compatibility and is shown in `kubectl get` output
// only as a quick-glance summary.
const (
	// ConditionReady is True when the policy has been translated and the
	// generated ConfigMap is in sync with the latest spec generation.
	ConditionReady = "Ready"

	// ConditionPolicyValid is True when the spec passed validation and
	// translation. False indicates a structural problem in the spec
	// (Reason explains what).
	ConditionPolicyValid = "PolicyValid"

	// ConditionEnforceCapable is True when at least one node in scope is
	// running an Aegis daemon that reports the kernel features required to
	// enforce this policy (BPF LSM, BTF, ringbuf, plus any feature gates
	// the spec opted into such as IMA appraisal). False with a Reason of
	// e.g. `BPFLSMUnavailable` tells the operator exactly why enforcement
	// is degraded.
	ConditionEnforceCapable = "EnforceCapable"

	// ConditionDegraded is True when the controller has hit a transient or
	// recoverable problem (e.g. ConfigMap update failed, daemon posture
	// not yet observed). It does not by itself indicate that enforcement
	// is broken — Ready and EnforceCapable carry that signal.
	ConditionDegraded = "Degraded"
)

// Standard condition reasons. These are stable strings that callers
// (dashboards, CI, alerting) can match on; do not rename without bumping
// the API version.
const (
	ReasonPolicyApplied           = "PolicyApplied"
	ReasonTranslationFailed       = "TranslationFailed"
	ReasonConfigMapWriteFailed    = "ConfigMapWriteFailed"
	ReasonAwaitingNodePosture     = "AwaitingNodePosture"
	ReasonBPFLSMUnavailable       = "BPFLSMUnavailable"
	ReasonIMAAppraisalUnavailable = "IMAAppraisalUnavailable"
	ReasonNoMatchingWorkloads     = "NoMatchingWorkloads"

	// ReasonLegacySelectorInUse is set on a Deprecated condition when a
	// policy uses the old `spec.selector` field instead of the new
	// `spec.workloadSelector`. The policy still reconciles normally; the
	// condition is informational.
	ReasonLegacySelectorInUse = "LegacySelectorInUse"

	// ReasonInvalidSelectorScope is set when a namespaced AegisPolicy
	// tries to select workloads outside its own namespace. Rejected by
	// the admission webhook; reconciler guards against it as defence in
	// depth.
	ReasonInvalidSelectorScope = "InvalidSelectorScope"

	// ReasonAllowBlockCollision is set when a single spec contains both
	// Allow and Block rules for the same literal target (e.g. the same
	// path listed twice with different actions). Rejected by the
	// admission webhook.
	ReasonAllowBlockCollision = "AllowBlockCollision"
)

// Non-standard condition types used by v0.5.0 policies.
//
// These are in addition to the standard Ready/PolicyValid/EnforceCapable/
// Degraded set above, not replacements.
const (
	// ConditionDeprecated is True when a policy uses a deprecated API
	// surface (currently: the legacy `spec.selector` field). The reason
	// will be one of the Reason* constants above (e.g.
	// ReasonLegacySelectorInUse).
	ConditionDeprecated = "Deprecated"
)

// AegisPolicyStatus defines the observed state of an Aegis policy.
//
// Operators should prefer the structured `Conditions` array for automation;
// `Phase`/`Message` are retained for human-friendly `kubectl get` output.
type AegisPolicyStatus struct {
	// Phase indicates the policy lifecycle phase. Retained for
	// backwards compatibility with the printer column. Automation should
	// prefer the Conditions array.
	// +kubebuilder:validation:Enum=Pending;Applied;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides a human-readable summary of the most recent
	// reconcile. Automation should prefer Conditions[*].Message.
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions report the current observed state of this policy.
	// Standard condition types are: Ready, PolicyValid, EnforceCapable,
	// Degraded. See the v1alpha1 package constants for reason strings.
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`

	// AppliedNodes is the number of nodes where this policy is active.
	// +optional
	AppliedNodes int `json:"appliedNodes,omitempty"`

	// LastAppliedAt is the timestamp of the last successful application.
	// +optional
	LastAppliedAt *metav1.Time `json:"lastAppliedAt,omitempty"`

	// PolicyHash is the SHA-256 hash of the generated policy content.
	// +optional
	PolicyHash string `json:"policyHash,omitempty"`

	// ObservedGeneration is the generation most recently observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

func init() {
	SchemeBuilder.Register(
		&AegisPolicy{},
		&AegisPolicyList{},
		&AegisClusterPolicy{},
		&AegisClusterPolicyList{},
	)
}
