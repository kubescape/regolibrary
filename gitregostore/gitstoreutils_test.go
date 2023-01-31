package gitregostore

import (
	"testing"
)

func Test_isControlID(t *testing.T) {
	tests := []struct {
		name string
		c    string
		want bool
	}{
		{
			name: "C-XXXX format 00",
			c:    "C-0000",
			want: true,
		},
		{
			name: "C-XXXX format 01",
			c:    "c-0000",
			want: true,
		},
		{
			name: "C-XXXX format 02",
			c:    "c-1234",
			want: true,
		},
		{
			name: "C-XXXX format 03",
			c:    "C-1234",
			want: true,
		},
		{
			name: "C-XXXX format 04",
			c:    "C-1234",
			want: true,
		},
		{
			name: "C-XXXX format 05",
			c:    "C1234",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 00",
			c:    "C-12345",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 01",
			c:    "C-123",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 02",
			c:    "CC-1234",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 03",
			c:    "CIS-v1.6.1-4.1.3",
			want: true,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 04",
			c:    "CIS-vv1.6.1-4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 05",
			c:    "CIS-v1.6.1-v4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 06",
			c:    "CIS-v1.6.1 4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 07",
			c:    "CIS-CIS-v1.6.1-4.1.3",
			want: false,
		},
		{
			name: "NAME-[vVERSION]-NUMBER.[NUMBER.][NUMBER.]... format 08",
			c:    "CiS-v1.6.1-4.1.3",
			want: false,
		},
		{
			name: "control name 00",
			c:    "control-name-minuses",
			want: false,
		},
		{
			name: "control name 01",
			c:    "control name spaces",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlID(tt.c); got != tt.want {
				t.Errorf("isControlID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGitRegoStore_setURL(t *testing.T) {
	type fields struct {
		BaseUrl    string
		Owner      string
		Repository string
		Branch     string
		Path       string
		Tag        string
	}
	tests := []struct {
		name      string
		fields    fields
		wantedURL string
	}{
		{
			name: "setURL 00",
			fields: fields{
				BaseUrl:    "https://github.com",
				Owner:      "kubescape",
				Repository: "regolibrary",
				Branch:     "releases",
				Path:       "latest/download",
				Tag:        "",
			},
			wantedURL: "https://github.com/kubescape/regolibrary/releases/latest/download",
		},
		{
			name: "setURL 01",
			fields: fields{
				BaseUrl:    "https://raw.githubusercontent.com",
				Owner:      "kubescape",
				Repository: "regolibrary",
				Branch:     "dev",
				Path:       "releaseDev",
				Tag:        "",
			},
			wantedURL: "https://raw.githubusercontent.com/kubescape/regolibrary/dev/releaseDev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gs := &GitRegoStore{
				BaseUrl:    tt.fields.BaseUrl,
				Owner:      tt.fields.Owner,
				Repository: tt.fields.Repository,
				Branch:     tt.fields.Branch,
				Path:       tt.fields.Path,
				Tag:        tt.fields.Tag,
			}
			gs.setURL()
			if gs.URL != tt.wantedURL {
				t.Errorf("setURL() = %v, want %v", gs.URL, tt.wantedURL)
			}
		})
	}
}
