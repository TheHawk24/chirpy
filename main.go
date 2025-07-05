package main

import (
	"net/http"
)

func main() {

	mux := http.NewServeMux()
	//Server index.html
	mux.Handle("/app", http.StripPrefix("/app", http.FileServer(http.Dir("./"))))
	mux.Handle("/app/assets/", http.StripPrefix("/app/assets", http.FileServer(http.Dir("./assets"))))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		msg := []byte("OK")
		w.Write(msg)
	})
	server := http.Server{}
	server.Handler = mux
	server.Addr = ":8080"

	//Listen on bind address
	server.ListenAndServe()
}
