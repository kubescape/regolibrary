package armo_builtins



deny[msg] {
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
	s1 := [s1 | s1 = rolebindings[_].subjects]

    clusterrolebindings := [clusterrolebinding | clusterrolebinding = input[_]; clusterrolebinding.kind == "ClusterRoleBinding"]
	s2 := [s2 | s2 = clusterrolebindings[_].subjects]

    subjects := array.concat(s1,s2)

    msg := subjects
}
