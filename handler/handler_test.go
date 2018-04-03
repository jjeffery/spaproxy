package handler

import "testing"

func TestIsSameSite(t *testing.T) {
	tests := []struct {
		referrer   string
		siteURL    string
		isSameSite bool
	}{
		{
			referrer:   "https://abc.com/1234.html",
			siteURL:    "https://abc.com",
			isSameSite: true,
		},
		{
			referrer:   "https://abc.com/1234.html",
			siteURL:    "https://abc.com/",
			isSameSite: true,
		},
		{
			referrer:   "https://abc.com/1234.html",
			siteURL:    "HTTPS://ABC.COM/",
			isSameSite: true,
		},
		{
			// can't get away with a simple prefix: need slashes in the right place
			referrer:   "https://abc.com.au/1234.html",
			siteURL:    "https://abc.com",
			isSameSite: false,
		},
		{
			// can't get away with a simple prefix: need slashes in the right place
			referrer:   "https://abc.com/1234.html",
			siteURL:    "https://abc.com/1234",
			isSameSite: false,
		},
		{
			// can't get away with a simple prefix: need slashes in the right place
			referrer:   "https://abc.com/1234.html",
			siteURL:    "https://abc.com/base",
			isSameSite: false,
		},
	}

	for tn, tt := range tests {
		if got, want := isSameSite(tt.referrer, tt.siteURL), tt.isSameSite; got != want {
			t.Errorf("%d: got=%v, want=%v", tn, got, want)
		}
	}
}
