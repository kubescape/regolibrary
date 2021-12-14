	package armo_builtins
	# import data.cautils as cautils
	# import data.kubernetes.api.client as client
	import data

	deny[msga] {
		pod := input[_]
		pod.kind == "Pod"
		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := pod.spec.containers[i]
		env := container.env[j]
		contains(lower(env.name), key_name)
		isNotReference(env)
		path := sprintf("spec.containers[%v].env[%v]", [format_int(i, 10), format_int(j, 10)])

		msga := {
			"alertMessage": sprintf("Pod: %v has sensitive information in environment variables", [pod.metadata.name]),
			"alertScore": 9,
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

		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := wl.spec.template.spec.containers[i]
		env := container.env[j]
		contains(lower(env.name), key_name)
		isNotReference(env)
		path := sprintf("spec.template.spec.containers[%v].env[%v]", [format_int(i, 10), format_int(j, 10)])	

		msga := {
			"alertMessage": sprintf("%v: %v has sensitive information in environment variables", [wl.kind, wl.metadata.name]),
			"alertScore": 9,
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
		sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
		key_name := sensitive_key_names[_]
		container := wl.spec.jobTemplate.spec.template.spec.containers[i]
		env := container.env[j]
		contains(lower(env.name), key_name)
		isNotReference(env)
		path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].env[%v]", [format_int(i, 10), format_int(j, 10)])

		msga := {
			"alertMessage": sprintf("Cronjob: %v has sensitive information in environment variables", [wl.metadata.name]),
			"alertScore": 9,
			"failedPaths": [path],
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [wl]
			}
		}
	}



	isNotReference(env)
	{
		not env.valueFrom.secretKeyRef
		not env.valueFrom.configMapKeyRef
	}

