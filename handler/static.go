package handler

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/jjeffery/errors"
	"github.com/jjeffery/spaproxy/amzn"
	"github.com/jjeffery/spaproxy/config"
	"github.com/jjeffery/spaproxy/s3proxy"
)

func newStaticAssetsHandler() (http.Handler, error) {
	u, err := url.Parse(config.File.StaticAssets.URL)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse static assets URL").With(
			"url", config.File.StaticAssets.URL,
		)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return newHttpHandler(u)
	case "s3":
		return newS3Handler(u)
	default:
		return nil, errors.New("unsupported URL scheme, expecting http, https or s3").With(
			"url", config.File.StaticAssets.URL,
		)
	}
}

func newS3Handler(u *url.URL) (http.Handler, error) {
	bucket := u.Hostname()
	prefix := strings.TrimPrefix(u.Path, "/")
	h := s3proxy.New(bucket,
		s3proxy.WithAWSSession(amzn.Session()),
		s3proxy.WithKeyPrefix(prefix),
		s3proxy.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			log.Println("error:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}), nil
}

func newHttpHandler(u *url.URL) (http.Handler, error) {
	return httputil.NewSingleHostReverseProxy(u), nil
}
