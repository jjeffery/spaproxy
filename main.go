package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jjeffery/kv"
	"github.com/jjeffery/shutdown"
	"github.com/jjeffery/spaproxy/config"
	"github.com/jjeffery/spaproxy/handler"
)

func main() {
	if err := config.Load(); err != nil {
		log.Fatalln("fatal:", err)
	}

	h, err := handler.New()
	if err != nil {
		log.Fatalln("fatal:", err)
	}

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
