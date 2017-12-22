package handler

import (
	"log"
	"net/http"

	"github.com/jjeffery/spaproxy/amzn"
	"github.com/jjeffery/spaproxy/config"
	"github.com/jjeffery/spaproxy/s3proxy"
)

func newStaticAssetsHandler() http.HandlerFunc {
	h := s3proxy.New(config.File.StaticAssets.Bucket,
		s3proxy.WithAWSSession(amzn.Session()),
		s3proxy.WithKeyPrefix(config.File.StaticAssets.Prefix),
		s3proxy.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			log.Println("error:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})
}
