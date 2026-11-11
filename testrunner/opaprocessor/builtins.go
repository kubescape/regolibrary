package opaprocessor

import (
	"fmt"

	"github.com/distribution/reference"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
)

// Kubescape registers extra builtins before evaluating rules
// (core/pkg/opaprocessor in kubescape/kubescape). The ones below are mirrored
// here so that rules calling them can have test fixtures.

var imageNameNormalizeDeclaration = &rego.Function{
	Name:    "image.parse_normalized_name",
	Decl:    types.NewFunction(types.Args(types.S), types.S),
	Memoize: true,
}

func imageNameNormalizeDefinition(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	aStr, err := builtins.StringOperand(a.Value, 1)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}
	name, err := reference.ParseNormalizedNamed(string(aStr))
	if err != nil {
		return nil, err
	}
	return ast.StringTerm(name.String()), nil
}

func init() {
	rego.RegisterBuiltin1(imageNameNormalizeDeclaration, imageNameNormalizeDefinition)
}
