# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	policy := input[_]
	policy.kind == "NetworkPolicy"
	selector := object.get(policy.spec, "podSelector", {})
	selector_defined(selector)
	namespace := object.get(policy.metadata, "namespace", "default")

	not has_matching_workload(policy, namespace, input)

	msga := {
		"alertMessage": sprintf("NetworkPolicy '%v' podSelector matches no workloads in namespace '%v'", [policy.metadata.name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.podSelector"],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [policy]},
	}
}

has_matching_workload(policy, namespace, resources) if {
	selector := object.get(policy.spec, "podSelector", {})
	wl := resources[_]
	is_workload(wl)
	wl_namespace := object.get(wl.metadata, "namespace", "default")
	wl_namespace == namespace
	selector_matches(selector, pod_template_labels(wl))
}

# selector_defined is required: an empty selector means "select all pods" and
# must never be flagged dangling, even in an empty namespace where
# has_matching_workload would otherwise find nothing.
selector_defined(selector) if {
	count(object.get(selector, "matchLabels", {})) > 0
}
selector_defined(selector) if {
	count(object.get(selector, "matchExpressions", [])) > 0
}

# Full LabelSelector semantics: matchLabels AND matchExpressions. Both empty
# would match everything, but selector_defined already excludes that case.
selector_matches(selector, labels) if {
	not match_labels_mismatch(object.get(selector, "matchLabels", {}), labels)
	not match_expressions_mismatch(object.get(selector, "matchExpressions", []), labels)
}

match_labels_mismatch(match_labels, labels) if {
	match_labels[k]
	not labels[k] == match_labels[k]
}

match_expressions_mismatch(expressions, labels) if {
	expression := expressions[_]
	not expression_matches(expression, labels)
}

expression_matches(expression, labels) if {
	expression.operator == "In"
	label_value := labels[expression.key]
	label_value in object.get(expression, "values", [])
}
expression_matches(expression, labels) if {
	expression.operator == "NotIn"
	not labels[expression.key]
}
expression_matches(expression, labels) if {
	expression.operator == "NotIn"
	label_value := labels[expression.key]
	not label_value in object.get(expression, "values", [])
}
expression_matches(expression, labels) if {
	expression.operator == "Exists"
	labels[expression.key]
}
expression_matches(expression, labels) if {
	expression.operator == "DoesNotExist"
	not labels[expression.key]
}

is_workload(wl) if {
	workload_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicationController"}
	workload_kinds[wl.kind]
}

pod_template_labels(wl) := labels if {
	wl.kind == "Pod"
	labels := object.get(wl.metadata, "labels", {})
}
pod_template_labels(wl) := labels if {
	controller_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	controller_kinds[wl.kind]
	labels := object.get(wl.spec.template.metadata, "labels", {})
}
pod_template_labels(wl) := labels if {
	wl.kind == "CronJob"
	labels := object.get(wl.spec.jobTemplate.spec.template.metadata, "labels", {})
}
