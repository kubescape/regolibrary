package gitregostore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gs_tests(t *testing.T, gs *GitRegoStore) {
	index := 0

	t.Run("should retrieve OPA rules (policies)", func(t *testing.T) {
		t.Parallel()

		policies, err := gs.GetOPAPolicies()
		assert.NoError(t, err)
		assert.NotNilf(t, policies,
			"failed to get all policies %v", err,
		)
	})

	t.Run("should retrieve OPA policy names", func(t *testing.T) {
		t.Parallel()

		policiesNames, err := gs.GetOPAPoliciesNamesList()
		require.NoError(t, err)
		require.NotEmptyf(t, policiesNames,
			"failed to get policies names list %v", err,
		)

		require.Greater(t, len(policiesNames), index)

		t.Run("should retrieve OPA policy by name", func(t *testing.T) {
			t.Parallel()

			policy, err := gs.GetOPAPolicyByName(policiesNames[index])
			assert.NoError(t, err)
			assert.NotNilf(t, policy,
				"failed to get policy by name: '%s', %v", policiesNames[index], err,
			)
		})
	})

	t.Run("should retrieve OPA controls", func(t *testing.T) {
		t.Parallel()

		controls, err := gs.GetOPAControls()
		assert.NoError(t, err)
		assert.NotEmptyf(t, controls,
			"failed to get all controls %v", err,
		)
	})

	t.Run("should retrieve OPA controls names", func(t *testing.T) {
		t.Parallel()

		controlsNames, err := gs.GetOPAControlsNamesList()
		require.NoError(t, err)
		require.NotEmptyf(t, controlsNames,
			"failed to get controls names list %v", err,
		)

		require.Greater(t, len(controlsNames), index)

		t.Run("should retrieve OPA control by name", func(t *testing.T) {
			t.Parallel()

			control, err := gs.GetOPAControlByName(controlsNames[index])
			assert.NoError(t, err)
			assert.NotNilf(t, control,
				"failed to get control by name: '%s', %v", controlsNames[index], err,
			)
		})
	})

	t.Run("should retrieve OPA controls IDs", func(t *testing.T) {
		t.Parallel()

		controlsIDs, err := gs.GetOPAControlsIDsList()
		require.NoError(t, err)
		require.NotEmptyf(t, controlsIDs,
			"failed to get controls ids list %v", err,
		)

		require.Greater(t, len(controlsIDs), index)

		t.Run("should retrieve OPA control by ID", func(t *testing.T) {
			t.Parallel()

			control, err := gs.GetOPAControlByID(controlsIDs[index])
			assert.NoError(t, err)
			assert.NotNilf(t, control,
				"failed to get control by ID: '%s', %v", controlsIDs[index], err,
			)
		})
	})

	t.Run("should retrieve OPA frameworks", func(t *testing.T) {
		t.Parallel()

		frameworks, err := gs.GetOPAFrameworks()
		assert.NoError(t, err)
		assert.NotEmptyf(t, frameworks,
			"failed to get all frameworks %v", err,
		)
	})

	t.Run("should retrieve OPA frameworks names", func(t *testing.T) {
		t.Parallel()

		frameworksNames, err := gs.GetOPAFrameworksNamesList()
		require.NoError(t, err)
		require.NotEmptyf(t, frameworksNames,
			"failed to get frameworks names list %v", err,
		)

		t.Run("should retrieve OPA framework by name", func(t *testing.T) {
			t.Parallel()

			framework, err := gs.GetOPAFrameworkByName(frameworksNames[0])
			assert.NoError(t, err)
			assert.NotNilf(t, framework,
				"failed to get framework by name: '%s', %v", frameworksNames[0], err,
			)

			assert.NotEmptyf(t, framework.Controls,
				"failed to get controls for framework name: '%s'", framework.Name,
			)

			require.NotNil(t, framework.ControlsIDs)
			assert.NotEmptyf(t, *framework.ControlsIDs,
				"failed to get controls ids for framework name: '%s'", framework.Name,
			)

			for _, control := range framework.Controls {
				assert.NotEmptyf(t, control.Rules,
					"failed to get rules for framework name: '%s', control name: '%s'", framework.Name, control.Name,
				)
			}
		})
	})

	t.Run("should retrieve OPA control by names", func(t *testing.T) {
		t.Parallel()

		control, err := gs.GetOPAControlByFrameworkNameAndControlName("NSA", "Allow privilege escalation")
		assert.NoError(t, err)
		require.NotNilf(t, control,
			"failed to get control by framework name 'NSA' and control name 'Allow privilege escalation': %v", err,
		)
		assert.Equalf(t, "c-0016", strings.ToLower(control.ControlID),
			"wrong control for framework name 'NSA' and control name 'Allow privilege escalation' expected: 'C-0016', found %s", control.ControlID,
		)
	})
}

func TestGetPoliciesMethodsNew(t *testing.T) {
	t.Parallel()

	gs := NewDefaultGitRegoStore(-1)
	t.Run("shoud set objects in rego store", func(t *testing.T) {
		require.NoError(t, gs.SetRegoObjects())
	})

	gs_tests(t, gs)

}

func TestGetOPAFrameworkByName(t *testing.T) {
	t.Parallel()

	gs := NewDevGitRegoStore(-1)

	t.Run("shoud set objects in rego store", func(t *testing.T) {
		require.NoError(t, gs.SetRegoObjects())
	})

	t.Run("shoud retrieve CIS framework", func(t *testing.T) {
		_, err := gs.GetOPAFrameworkByName("CIS")
		require.NoErrorf(t, err,
			"failed to get framework object: %v", err,
		)
	})
}

func TestGetPoliciesMethodsDevNew(t *testing.T) {
	t.Parallel()

	gs := NewDevGitRegoStore(-1)

	t.Run("should set the rego store", func(t *testing.T) {
		require.NoError(t, gs.SetRegoObjects())
	})

	gs_tests(t, gs)
}
