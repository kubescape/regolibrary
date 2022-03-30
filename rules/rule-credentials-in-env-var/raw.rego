	package armo_builtins
	import data

	deny[msga] {
		pod := input[_]
		pod.kind == "Pod"

		container := pod.spec.containers[i]
		env := container.env[j]
		env.value != ""

		is_sensitive_key_name(env.name)
		is_not_reference(env)

		path := sprintf("spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])

		msga := {
			"alertMessage": sprintf("Pod: %v has sensitive information in environment variables", [pod.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"failedPaths": [path],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [pod]
			}
		}
	}

	deny[msga] {
		wl := input[_]
		spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
		spec_template_spec_patterns[wl.kind]

		container := wl.spec.template.spec.containers[i]
		env := container.env[j]
		env.value != ""

		is_sensitive_key_name(env.name)
		is_not_reference(env)

		path := sprintf("spec.template.spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])	

		msga := {
			"alertMessage": sprintf("%v: %v has sensitive information in environment variables", [wl.kind, wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"failedPaths": [path],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}

	deny[msga] {
		wl := input[_]
		wl.kind == "CronJob"
		container := wl.spec.jobTemplate.spec.template.spec.containers[i]
		env := container.env[j]
		env.value != ""

		is_sensitive_key_name(env.name)
		is_not_reference(env)

		path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [format_int(i, 10), format_int(j, 10)])

		msga := {
			"alertMessage": sprintf("Cronjob: %v has sensitive information in environment variables", [wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"failedPaths": [path],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}



is_not_reference(env)
{
	not env.valueFrom.secretKeyRef
	not env.valueFrom.configMapKeyRef
}

# see default-config-inputs.json for list values
is_sensitive_key_name(env_name)
{
	sensitive_key_name := data.postureControlInputs.sensitiveKeyNames[_]
	contains(lower(env_name), sensitive_key_name)
	# check that sensitive key name is not on allowlist
	data.postureControlInputs.sensitiveKeyNamesAllowlist
	sensitive_key_names_allowed_list := [sensitive_key_names_allowed |  sensitive_key_names_allowed= data.postureControlInputs.sensitiveKeyNamesAllowlist[_]; contains(lower(env_name), sensitive_key_names_allowed)]
	count(sensitive_key_names_allowed_list) == 0
}

is_sensitive_key_name(env_name)
{
	sensitive_key_name := data.postureControlInputs.sensitiveKeyNames[_]
	contains(lower(env_name), sensitive_key_name)
	not data.postureControlInputs.sensitiveKeyNamesAllowlist
}
