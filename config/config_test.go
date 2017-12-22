package config

import (
	"reflect"
	"testing"

	"github.com/hashicorp/hcl"
)

func equalString(t *testing.T, got, want string) {
	if got != want {
		t.Fatalf("got=%q, want=%q", got, want)
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		hcl    string
		failed bool
		data   Config
	}{
		{
			hcl: `
			SiteURL = "http://localhost:8080"

			StaticAssets {
				Bucket = "bucket-name"
				Prefix = "prefix"
			}
			
			Session {
				Table = "table-name"
				Secret = "a secret"
				PreviousSecret = "another secret"
			}
			
			OAuth2 {
				AuthURL = "1"
				TokenURL = "2"
				LogoutURL = "3"
				ClientID = "4"
				ClientSecret = "5"
			}`,
			data: Config{
				SiteURL: "http://localhost:8080",
				StaticAssets: S3Config{
					Bucket: "bucket-name",
					Prefix: "prefix",
				},
				Session: SessionConfig{
					Table:          "table-name",
					Secret:         "a secret",
					PreviousSecret: "another secret",
				},
				OAuth2: OAuth2Config{
					AuthURL:      "1",
					TokenURL:     "2",
					LogoutURL:    "3",
					ClientID:     "4",
					ClientSecret: "5",
				},
			},
		},
	}

	for tn, tt := range tests {
		var data Config
		err := hcl.Unmarshal([]byte(tt.hcl), &data)
		if err != nil {
			if !tt.failed {
				t.Fatalf("%d: cannot unmarshal: %v", tn, err)
			}
		}

		if !reflect.DeepEqual(data, tt.data) {
			t.Fatalf("%d: data not equal:\ngot: %v\bwant: %v", tn, data, tt.data)
		}
	}
}
