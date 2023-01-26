package gitregostore

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestGetNewControlID(t *testing.T) {
	controlIDS_tests := []struct {
		name        string
		controlID   string
		expectedRes string
	}{
		{
			name:        "ControlID_exists_in_mapping_uppercase",
			controlID:   "CIS-1.1.1",
			expectedRes: "C-0092",
		},
		{
			name:        "ControlID_exists_in_mapping_lowercase",
			controlID:   "cis-1.1.1",
			expectedRes: "C-0092",
		},
		{
			name:        "ControlID_doestexists_in_mapping",
			controlID:   "IDontExist",
			expectedRes: "IDontExist",
		},
	}

	for _, tt := range controlIDS_tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newControlID(tt.controlID)
			assert.Equal(t, tt.expectedRes, res)
		})
	}
}

func TestBaseControlName(t *testing.T) {
	controlIDS_tests := []struct {
		name        string
		controlID   string
		controlName string
		expectedRes string
	}{
		{
			name:        "ControlID_cis_uppercase",
			controlID:   "C-0092",
			controlName: "CIS-1.1.1 Control Name A",
			expectedRes: "Control Name A",
		},
		{
			name:        "ControlID_cis_lowercase",
			controlID:   "c-0092",
			controlName: "CIS-1.1.1 Control Name B",
			expectedRes: "Control Name B",
		},
		{
			name:        "ControlID_not_cis",
			controlID:   "NotRelevant",
			controlName: "NotCIS name",
			expectedRes: "NotCIS name",
		},
	}

	for _, tt := range controlIDS_tests {
		t.Run(tt.name, func(t *testing.T) {
			res := baseControlName(tt.controlID, tt.controlName)
			assert.Equal(t, tt.expectedRes, res)
		})
	}
}
