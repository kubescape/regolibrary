package armo_builtins

import rego.v1

# CIS 3.2.2 https://workbench.cisecurity.org/sections/1126657/recommendations/1838583

deny contains msga if {
	obj := input[_]
	is_api_server_info(obj)
	api_server_info := obj.data.APIServerInfo

	not contains(api_server_info.cmdLine, "--audit-policy-file")

	msga := {
		"alertMessage": "audit logs are not enabled",
		"alertScore": 5,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": api_server_info.cmdLine,
		}},
	}
}

deny contains msga if {
	obj := input[_]
	is_api_server_info(obj)

	api_server_info := obj.data.APIServerInfo

	contains(api_server_info.cmdLine, "--audit-policy-file")

	rawPolicyFile := api_server_info.auditPolicyFile
	policyFile = yaml.unmarshal(base64.decode(rawPolicyFile.content))

	are_audit_file_rules_valid(policyFile.rules)

	failed_obj := json.patch(policyFile, [{
		"op": "add",
		"path": "metadata",
		"value": {"name": sprintf("%s - Audit policy file", [obj.metadata.name])},
	}])

	msga := {
		"alertMessage": "audit policy rules do not cover key security areas or audit levels are invalid",
		"alertScore": 5,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"externalObjects": failed_obj},
	}
}

# Sample rules object
# rules:
# - level: RequestResponse
#   resources:
#   - group: ""
#     resources: ["pods"]
are_audit_file_rules_valid(rules) if {
	seeked_resources_with_audit_level := {
		"secrets": {
			"auditLevel": "Metadata",
			"mode": "equal",
		},
		"configmaps": {
			"auditLevel": "Metadata",
			"mode": "equal",
		},
		"tokenreviews": {
			"auditLevel": "Metadata",
			"mode": "equal",
		},
		"pods": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
		"deployments": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
		"pods/exec": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
		"pods/portforward": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
		"pods/proxy": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
		"services/proxy": {
			"auditLevel": "None",
			"mode": "not-equal",
		},
	}

	# Policy file must contain every resource
	some resource, config in seeked_resources_with_audit_level

	# Every seeked resource mu have valid audit levels
	not test_all_rules_against_one_seeked_resource(resource, config, rules)
}

test_all_rules_against_one_seeked_resource(seeked_resource, value_of_seeked_resource, rules) if {
	# Filter down rules to only those concerning a seeked resource
	rules_with_seeked_resource := [rule | rule := rules[_]; is_rule_concering_seeked_resource(rule, seeked_resource)]
	rules_count := count(rules_with_seeked_resource)

	# Move forward only if there are some
	rules_count > 0

	# Check if rules concerning seeked resource have valid audit levels
	valid_rules := [rule | rule := rules_with_seeked_resource[_]; validate_rule_audit_level(rule, value_of_seeked_resource)]
	valid_rules_count := count(valid_rules)

	valid_rules_count > 0

	# Compare all rules for that specififc resource with those with valid rules, if amount of them differs,
	# it means that there are also some rules which invalid audit level
	valid_rules_count == rules_count
}

is_rule_concering_seeked_resource(rule, seeked_resource) if {
	seeked_resource in rule.resources[_].resources
}

# Sample single rule:
#  	 level: RequestResponse
#    resources:
#    - group: ""
#      resources: ["pods"]
validate_rule_audit_level(rule, value_of_seeked_resource) := result if {
	value_of_seeked_resource.mode == "equal"
	result := rule.level == value_of_seeked_resource.auditLevel
} else := result if {
	result := rule.level != value_of_seeked_resource.auditLevel
}

is_api_server_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}
