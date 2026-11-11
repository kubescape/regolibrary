package opaprocessor

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageParseNormalizedName(t *testing.T) {
	tests := []struct {
		image    string
		expected string
	}{
		{image: "nginx", expected: "docker.io/library/nginx"},
		{image: "nginx:1.27", expected: "docker.io/library/nginx:1.27"},
		{image: "bitnami/redis", expected: "docker.io/bitnami/redis"},
		{image: "quay.io/kubescape/kubescape:v3", expected: "quay.io/kubescape/kubescape:v3"},
		{image: "localhost:5000/app@sha256:4b7a7f0c3e6b7d1f0a5d0a7d6f8e3b2c1a9f8e7d6c5b4a3928170f6e5d4c3b2a", expected: "localhost:5000/app@sha256:4b7a7f0c3e6b7d1f0a5d0a7d6f8e3b2c1a9f8e7d6c5b4a3928170f6e5d4c3b2a"},
	}
	for _, tc := range tests {
		t.Run(tc.image, func(t *testing.T) {
			rs, err := rego.New(
				rego.Query("x := image.parse_normalized_name(input)"),
				rego.Input(tc.image),
			).Eval(context.Background())
			require.NoError(t, err)
			require.Len(t, rs, 1)
			assert.Equal(t, tc.expected, rs[0].Bindings["x"])
		})
	}
}

func TestImageParseNormalizedNameInvalid(t *testing.T) {
	rs, err := rego.New(
		rego.Query("x := image.parse_normalized_name(input)"),
		rego.Input("Not A Valid/Image"),
	).Eval(context.Background())
	require.NoError(t, err)
	assert.Empty(t, rs, "an invalid reference leaves the call undefined")
}
