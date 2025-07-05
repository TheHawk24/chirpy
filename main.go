package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) requestsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	msg := fmt.Sprintf("Hits: %v", cfg.fileserverHits.Load())
	w.Write([]byte(msg))
}

func (cfg *apiConfig) resetCount(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	msg := []byte("Sucessfully reset")
	w.Write(msg)
}

func main() {

	mux := http.NewServeMux()
	api_cfg := apiConfig{}
	//Server index.html
	assets_handler := http.FileServer(http.Dir("./assets"))
	index_handler := http.FileServer(http.Dir("./"))
	mux.Handle("/app/", http.StripPrefix("/app", api_cfg.middlewareMetricsInc(index_handler)))
	mux.Handle("/app/assets/", http.StripPrefix("/app/assets", api_cfg.middlewareMetricsInc(assets_handler)))
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		msg := []byte("OK")
		w.Write(msg)
	})
	mux.HandleFunc("GET /api/metrics", api_cfg.requestsCount)
	mux.HandleFunc("POST /api/reset", api_cfg.resetCount)
	server := http.Server{}
	server.Handler = mux
	server.Addr = ":8080"

	//Listen on bind address
	server.ListenAndServe()
}
