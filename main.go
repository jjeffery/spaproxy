package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/jjeffery/apigatewayproxy"
	"github.com/jjeffery/kv"
	"github.com/jjeffery/shutdown"
	"github.com/jjeffery/spaproxy/config"
	"github.com/jjeffery/spaproxy/handler"
)

// vars set by goreleaser
var (
	version = "unversioned"
	commit  = "no-revision"
	date    = "no-date"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(versionText())
		os.Exit(64) // sysexits.Usage
	}

	isLambda := apigatewayproxy.IsLambda()
	if isLambda {
		// cloudwatch logs already include the timestamp
		log.SetFlags(0)
	}

	if err := config.Load(); err != nil {
		log.Fatalln("fatal:", err)
	}

	h, err := newHandler()
	if err != nil {
		log.Fatalln("fatal:", err)
	}

	if isLambda {
		apigatewayproxy.Start(h)
		return
	}

	// not a lambda: run as a web server
	addr := ":8080"
	if port, ok := os.LookupEnv("PORT"); ok {
		addr = ":" + port
	}

	server := http.Server{
		Addr:    addr,
		Handler: h,
	}

	shutdown.RegisterCallback(func() {
		server.Shutdown(context.Background())
	})

	log.Println("listening", kv.List{
		"addr", addr,
	})
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalln("fatal: http server:", err)
	}
	log.Println("finished")
}

func newHandler() (http.Handler, error) {
	h, err := handler.New()
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_spaproxy/version" && r.Method == http.MethodGet {
			body := []byte(versionText())
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body)
			return
		}

		h.ServeHTTP(w, r)
	}), nil
}

func versionText() string {
	return fmt.Sprintf("version: %s\ncommit: %s\ndate: %s\n", version, commit, date)
}
