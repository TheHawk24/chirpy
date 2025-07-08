package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/TheHawk24/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	Db             *database.Queries
	platform       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) requestsCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200)
	msg := fmt.Sprintf(`<html>
	<body>
	<h1>Welcome, Chirpy Admin</h1>
	<p>Chirpy has been visited %d times!</p>
	</body>
	</html>`, cfg.fileserverHits.Load())
	//msg := fmt.Sprintf("Hits: %v", cfg.fileserverHits.Load())
	w.Write([]byte(msg))
}

func (cfg *apiConfig) resetCount(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		return
	}

	cfg.fileserverHits.Store(0)

	//Delete all records
	cfg.Db.DeleteUsers(r.Context())

	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	msg := []byte("Sucessfully reset")
	w.Write(msg)
}

func responseError(w http.ResponseWriter, msg_err string, resp_code int) {
	type errorResponse struct {
		Response string `json:"error"`
	}
	var e errorResponse
	e.Response = msg_err
	resp, err := json.Marshal(e)
	if err != nil {
		log.Printf("Error encoding error response: %s", err)
		return
	}
	w.WriteHeader(resp_code)
	w.Write(resp)
}

func parseRequest(w http.ResponseWriter, r *http.Request) {

	type params struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	var data params
	err := decoder.Decode(&data)
	if err != nil {
		log.Printf("Error decoding json data: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	if len(data.Body) > 140 {
		msg := "Chirp is too long"
		responseError(w, msg, 400)
		return
	}

	not_allowed := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Split(data.Body, " ")
	for i := 0; i < len(words); i++ {
		word := strings.ToLower(words[i])
		if not_allowed[word] {
			words[i] = "****"
		}
	}

	cleaned := strings.Join(words, " ")

	type msgOK struct {
		Cleaned_body string `json:"cleaned_body"`
	}

	var ok msgOK
	ok.Cleaned_body = cleaned
	resp, err := json.Marshal(ok)
	if err != nil {
		log.Printf("Faild to marshal respsonse: %s", err)
		msg := "Somethign went wrong"
		responseError(w, msg, 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(resp)
}

func (cfg apiConfig) newUser(w http.ResponseWriter, r *http.Request) {

	type client_data struct {
		Email string `json:"email"`
	}

	var data client_data
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		log.Printf("Failed to decode: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	if len(data.Email) == 0 {
		msg := "Please provide an email"
		responseError(w, msg, 400)
		return
	}

	user, err := cfg.Db.CreateUser(r.Context(), data.Email)
	if err != nil {
		log.Printf("Failed to create user: %s", err)
		msg := "Email already exists"
		responseError(w, msg, 409)
		return
	}

	type user_resp struct {
		Id         string `json:"id"`
		Created_at string `json:"created_at"`
		Updated_at string `json:"updated_at"`
		Email      string `json:"email"`
	}

	var json_user user_resp
	json_user.Id = user.ID.String()
	json_user.Created_at = user.CreatedAt.String()
	json_user.Updated_at = user.UpdatedAt.String()
	json_user.Email = user.Email

	json_data, err := json.Marshal(json_user)
	if err != nil {
		log.Printf("Failed to Marshal json data: %s", err)
		msg := "Failed to Marshal data"
		responseError(w, msg, 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(json_data)

}

func main() {

	//Database connection
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	pf := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database")
	}

	dbQueries := database.New(db)

	mux := http.NewServeMux()
	api_cfg := apiConfig{
		Db:       dbQueries,
		platform: pf,
	}

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
	mux.HandleFunc("GET /admin/metrics", api_cfg.requestsCount)
	mux.HandleFunc("POST /admin/reset", api_cfg.resetCount)
	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		parseRequest(w, r)
	})
	mux.HandleFunc("POST /api/users", api_cfg.newUser)
	server := http.Server{}
	server.Handler = mux
	server.Addr = ":8080"

	//Listen on bind address
	server.ListenAndServe()
}
