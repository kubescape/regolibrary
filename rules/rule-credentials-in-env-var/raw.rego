	package armo_builtins

	deny[msga] {
		pod := input[_]
		pod.kind == "Pod"
		# see default-config-inputs.json for list values
		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := pod.spec.containers[i]
		env := container.env[j]

		contains(lower(env.name), lower(key_name))
		env.value != ""

		is_not_reference(env)

		paths := [sprintf("spec.containers[%v].env[%v].name", [i, j]),
				  sprintf("spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("Pod: %v has sensitive information in environment variables", [pod.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
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

		# see default-config-inputs.json for list values
		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := wl.spec.template.spec.containers[i]
		env := container.env[j]

		contains(lower(env.name), lower(key_name))
		env.value != ""

		is_not_reference(env)

		paths := [sprintf("spec.template.spec.containers[%v].env[%v].name", [i, j]),
				sprintf("spec.template.spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("%v: %v has sensitive information in environment variables", [wl.kind, wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}

	deny[msga] {
		wl := input[_]
		wl.kind == "CronJob"
		# see default-config-inputs.json for list values
		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := wl.spec.jobTemplate.spec.template.spec.containers[i]
		env := container.env[j]

		contains(lower(env.name), lower(key_name))

		env.value != ""

		is_not_reference(env)

		paths := [sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [i, j]),
				  sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("Cronjob: %v has sensitive information in environment variables", [wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}

# check sensitive values
deny[msga] {
		pod := input[_]
		pod.kind == "Pod"
		# see default-config-inputs.json for list values
		sensitive_values := data.postureControlInputs.sensitiveValues
    	value := sensitive_values[_]
		container := pod.spec.containers[i]
		env := container.env[j]

		contains(lower(env.value), lower(value))

		is_not_reference(env)

		paths := [sprintf("spec.containers[%v].env[%v].name", [i, j]),
				  sprintf("spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("Pod: %v has sensitive information in environment variables", [pod.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
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

		# see default-config-inputs.json for list values
		sensitive_values := data.postureControlInputs.sensitiveValues
    	value := sensitive_values[_]
		container := wl.spec.template.spec.containers[i]
		env := container.env[j]

		contains(lower(env.value), lower(value))

		is_not_reference(env)

		paths := [sprintf("spec.template.spec.containers[%v].env[%v].name", [i, j]),
				sprintf("spec.template.spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("%v: %v has sensitive information in environment variables", [wl.kind, wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}

	deny[msga] {
		wl := input[_]
		wl.kind == "CronJob"
		# see default-config-inputs.json for list values
		sensitive_values := data.postureControlInputs.sensitiveValues
    	value := sensitive_values[_]
		container := wl.spec.jobTemplate.spec.template.spec.containers[i]
		env := container.env[j]

		contains(lower(env.value), lower(value))

		is_not_reference(env)

		paths := [sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].name", [i, j]),
				  sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v].value", [i, j])]

		msga := {
			"alertMessage": sprintf("Cronjob: %v has sensitive information in environment variables", [wl.metadata.name]),
			"alertScore": 9,
			"fixPaths": [],
			"deletePaths": paths,
			"failedPaths": paths,
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
