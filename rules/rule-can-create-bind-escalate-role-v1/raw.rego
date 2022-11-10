package armo_builtins

import future.keywords.in

# ================= create/update ===============================

# fails if user has access to create/update rolebindings/clusterrolebindings
deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rule := role.rules[p]

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verbs := ["create", "update", "patch", "*"]
	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | verb = rule.verbs[l]; verb in verbs]
	count(verb_path) > 0

	api_groups := ["rbac.authorization.k8s.io", "*"]
	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | apiGroup = rule.apiGroups[a]; apiGroup in api_groups]
	count(api_groups_path) > 0

	resources := ["rolebindings", "clusterrolebindings", "*"]
	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | resource = rule.resources[l]; resource in resources]
	count(resources_path) > 0

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [j]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can create/update rolebinding/clusterrolebinding", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# ================= bind ===============================

# fails if user has access to bind clusterroles/roles
deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")
	rule := role.rules[p]

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verbs := ["bind", "*"]
	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | verb = rule.verbs[l]; verb in verbs]
	count(verb_path) > 0

	api_groups := ["rbac.authorization.k8s.io", "*"]
	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | apiGroup = rule.apiGroups[a]; apiGroup in api_groups]
	count(api_groups_path) > 0

	resources := ["clusterroles", "roles", "*"]
	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | resource = rule.resources[l]; resource in resources]
	count(resources_path) > 0

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [j]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can bind roles/clusterroles", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"failedPaths": finalpath,
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": subjectVector,
		},
	}
}

# ================= escalate ===============================

# fails if user has access to escalate rolebindings/clusterrolebindings
deny[msga] {
	subjectVector := input[_]
	role := subjectVector.relatedObjects[i]
	rolebinding := subjectVector.relatedObjects[j]
	endswith(role.kind, "Role")
	endswith(rolebinding.kind, "Binding")

	rule := role.rules[p]

	subject := rolebinding.subjects[k]
	is_same_subjects(subjectVector, subject)

	rule_path := sprintf("relatedObjects[%d].rules[%d]", [i, p])

	verbs := ["escalate", "*"]
	verb_path := [sprintf("%s.verbs[%d]", [rule_path, l]) | verb = rule.verbs[l]; verb in verbs]
	count(verb_path) > 0

	api_groups := ["rbac.authorization.k8s.io", "*"]
	api_groups_path := [sprintf("%s.apiGroups[%d]", [rule_path, a]) | apiGroup = rule.apiGroups[a]; apiGroup in api_groups]
	count(api_groups_path) > 0

	resources := ["rolebindings", "clusterrolebindings", "*"]
	resources_path := [sprintf("%s.resources[%d]", [rule_path, l]) | resource = rule.resources[l]; resource in resources]
	count(resources_path) > 0

	path := array.concat(resources_path, verb_path)
	path2 := array.concat(path, api_groups_path)
	finalpath := array.concat(path2, [
		sprintf("relatedObjects[%d].subjects[%d]", [j, k]),
		sprintf("relatedObjects[%d].roleRef.name", [j]),
	])

	msga := {
		"alertMessage": sprintf("Subject: %s-%s can escalate rolebinding/clusterrolebinding", [subjectVector.kind, subjectVector.name]),
		"alertScore": 3,
		"failedPaths": finalpath,
		"fixPaths": [],
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
