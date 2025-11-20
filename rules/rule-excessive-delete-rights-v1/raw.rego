package armo_builtins

import future.keywords.in

# fails if user can can delete important resources
deny[msga] {
	# Use 'some' for explicit iteration - more efficient
	some subjectVector in input
	
	# Early filtering: check for required relatedObjects structure
	count(subjectVector.relatedObjects) > 0
	
	# Find role and rolebinding with explicit iteration
	some i
	role := subjectVector.relatedObjects[i]
	endswith(role.kind, "Role")
	
	some j
	rolebinding := subjectVector.relatedObjects[j]
	endswith(rolebinding.kind, "Binding")
	
	# Find matching rule - iterate only over role.rules
	some p
	rule := role.rules[p]
	
	# Check permissions early - fail fast if not matching
	# Use sets for O(1) membership checks
	verbs_set := {"delete", "deletecollection", "*"}
	some verb in rule.verbs
	verb in verbs_set
	
	api_groups_set := {"", "*", "apps", "batch"}
	some apiGroup in rule.apiGroups
	apiGroup in api_groups_set
	
	resources_set := {"secrets", "pods", "services", "deployments", "replicasets", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}
	some resource in rule.resources
	resource in resources_set
	
	# Only check subjects if permissions match
	some k
	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)
	
	# Build paths only after all checks pass - lazy evaluation
	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])
	
	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | 
		some l; verb := rule.verbs[l]; verb in verbs_set]
	
	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | 
		some a; apiGroup := rule.apiGroups[a]; apiGroup in api_groups_set]
	
	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | 
		some l; resource := rule.resources[l]; resource in resources_set]
	
	finalpath := array.concat(
		array.concat(resources_path, verb_path),
		array.concat(api_groups_path, [
			sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
			sprintf("relatedObjects[%d].roleRef.name", [j]),
		])
	)

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can delete important resources", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"fixPaths": [],
		"reviewPaths": finalpath,
		"failedPaths": finalpath,
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# for service accounts
is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.namespace == subject.namespace
}

# for users/ groups
is_same_subjects(subjectVector, subject) {
	subjectVector.kind == subject.kind
	subjectVector.name == subject.name
	subjectVector.apiGroup == subject.apiGroup
}
