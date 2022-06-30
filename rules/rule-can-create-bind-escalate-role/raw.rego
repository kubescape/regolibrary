
package armo_builtins
import data.cautils as cautils

# ================= create/update ===============================

# fails if user has access to create/update rolebindings/clusterrolebindings
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_create_update_to_role_resource(rule)
    can_create_update_to_role_verb(rule)
  
    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# fails if user has access to create/update rolebindings/clusterrolebindings
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_create_update_to_role_resource(rule)
    can_create_update_to_role_verb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# fails if user has access to create/update rolebindings/clusterrolebindings
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    can_create_update_to_role_resource(rule)
    can_create_update_to_role_verb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# ================= bind ===============================

# fails if user has access to bind clusterroles/roles
# RoleBinding to Role
deny [msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]

    can_bind_to_role_resource(rule)
    can_bind_to_role_verb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


# fails if user has access to bind clusterroles/roles
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    
    can_bind_to_role_resource(rule)
    can_bind_to_role_verb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


# fails if user has access to bind clusterroles/roles
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
can_bind_to_role_resource(rule)
    can_bind_to_role_verb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])
    	
   msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


# ================= escalate ===============================


# fails if user has access to escalate rolebindings/clusterrolebindings
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_escalate_to_role_resource(rule)
    can_escalate_to_role_verb(rule)
  
    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# fails if user has access to escalate rolebindings/clusterrolebindings
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    can_escalate_to_role_resource(rule)
    can_escalate_to_role_verb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# fails if user has access to escalate rolebindings/clusterrolebindings
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    can_escalate_to_role_resource(rule)
    can_escalate_to_role_verb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])
    	
  	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


# ============== escalate =====================

can_escalate_to_role_resource(rule){
     cautils.list_contains(rule.resources,"clusterroles")
}

can_escalate_to_role_resource(rule){
     cautils.list_contains(rule.resources,"roles")
}

can_escalate_to_role_resource(rule){
     is_api_group(rule)
     cautils.list_contains(rule.resources,"*")
}

can_escalate_to_role_verb(rule) {
       cautils.list_contains(rule.verbs, "escalate")
}

can_escalate_to_role_verb(rule) {
       cautils.list_contains(rule.verbs, "*")
}


# ============== bind =====================

can_bind_to_role_resource(rule){
     cautils.list_contains(rule.resources,"clusterroles")
}

can_bind_to_role_resource(rule){
     cautils.list_contains(rule.resources,"roles")
}

can_bind_to_role_resource(rule){
     is_api_group(rule)
     cautils.list_contains(rule.resources,"*")
}


can_bind_to_role_verb(rule) {
       cautils.list_contains(rule.verbs, "bind")
}

can_bind_to_role_verb(rule) {
       cautils.list_contains(rule.verbs, "*")
}

# ============== create/update =====================

can_create_update_to_role_resource(rule) {
      cautils.list_contains(rule.resources,"rolebindings")
}

can_create_update_to_role_resource(rule) {
      cautils.list_contains(rule.resources,"clusterrolebindings")
}

can_create_update_to_role_resource(rule) {
     is_api_group(rule)
     cautils.list_contains(rule.resources,"*")
}


can_create_update_to_role_verb(rule) {
     cautils.list_contains(rule.verbs, "create")
}

can_create_update_to_role_verb(rule) {
     cautils.list_contains(rule.verbs, "update")
}

can_create_update_to_role_verb(rule) {
     cautils.list_contains(rule.verbs, "patch")
}

can_create_update_to_role_verb(rule) {
     cautils.list_contains(rule.verbs, "*")
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "rbac.authorization.k8s.io"
}