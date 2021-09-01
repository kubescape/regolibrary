package armo_builtins


#Checks if RBAC is enabled
deny[msga] {
   apigouplist := input[_]
   groupVersions := [groupVersion | groupVersion = apigouplist.groups[_].versions[_].groupVersion]
	
	not list_contains(groupVersions, "rbac.authorization.k8s.io/v1")		
								
	msga := {
		"alertMessage": sprintf("%s", ["RBAC is not enabled for this cluster"]),
		"alertScore": 9,
		"packagename": "armo_builtins",
  		"alertObject": {
			"k8sApiObjects": []
		}

	}
}



# Fails is rolebinding gives permsisiosn to anonymous user
deny[msga] {
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    rolebinding := rolebindings[_]

    isAnonymous(rolebinding)

    	msga := {
	"alertMessage": sprintf("the following rolebinding: %v gives permissions to anonymous users", [rolebinding.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
  	"alertObject": {
			"k8sApiObjects": [rolebinding]
		}

	}
}


# Fails is clusterrolebinding gives permsisiosn to anonymous user
deny[msga] {
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    rolebinding := rolebindings[_]

    isAnonymous(rolebinding)

    	msga := {
	"alertMessage": sprintf("the following rolebinding: %v gives permissions to anonymous users", [rolebinding.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
  	"alertObject": {
			"k8sApiObjects": [rolebinding]
		}

	}
}
	
isAnonymous(binding) {
    subject := binding.subjects[_]
    subject.name == "system:anonymous"
}

isAnonymous(binding) {
    subject := binding.subjects[_]
    subject.name == "system:unauthenticated"
}

list_contains(list, element) {
  some i
  list[i] == element
}