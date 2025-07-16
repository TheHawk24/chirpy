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
	"time"

	"github.com/TheHawk24/chirpy/internal/auth"
	"github.com/TheHawk24/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	Db             *database.Queries
	platform       string
	Secret         string
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

func responseMsg(w http.ResponseWriter, status_code int, data interface{}) {

	msg, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal data: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status_code)
	w.Write(msg)
}

func responseError(w http.ResponseWriter, msg_err string, resp_code int) {
	type errorResponse struct {
		Response string `json:"error"`
	}
	var e errorResponse
	e.Response = msg_err
	responseMsg(w, resp_code, e)
	//w.WriteHeader(resp_code)
	//w.Write(resp)
}

func (cfg apiConfig) newChirp(w http.ResponseWriter, r *http.Request) {

	// Validate jwt
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 400)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.Secret)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	type params struct {
		Body string `json:"body"`
		//UserID string `json:"user_id"`
	}

	decoder := json.NewDecoder(r.Body)
	var data params
	err = decoder.Decode(&data)
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

	var chirp_params database.CreateChirpParams
	chirp_params.Body = cleaned

	//user_id, err := uuid.Parse(data.UserID)
	//if err != nil {
	//	log.Printf("Error parsing uuid: %s", err)
	//	msg := "Something went wrong"
	//	responseError(w, msg, 500)
	//	return
	//}
	chirp_params.UserID = userID

	chirp, err := cfg.Db.CreateChirp(r.Context(), chirp_params)
	if err != nil {
		log.Printf("Failed to create chirp: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	type msgOK struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    string    `json:"user_id"`
	}

	var ok msgOK
	ok.ID = chirp.ID.String()
	ok.CreatedAt = chirp.CreatedAt
	ok.UpdatedAt = chirp.UpdatedAt
	ok.UserID = chirp.UserID.String()
	ok.Body = chirp.Body

	responseMsg(w, 201, ok)
	//w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(201)
	//w.Write(resp)
}

func (cfg apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	chirps, err := cfg.Db.GetChirps(r.Context())
	if err != nil {
		log.Printf("Failed to retrieve chirps from database: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	type msgOK struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	msgs := make([]msgOK, len(chirps))

	for i := 0; i < len(chirps); i++ {
		msgs[i].ID = chirps[i].ID.String()
		msgs[i].CreatedAt = chirps[i].CreatedAt.String()
		msgs[i].UpdatedAt = chirps[i].UpdatedAt.String()
		msgs[i].UserID = chirps[i].UserID.String()
		msgs[i].Body = chirps[i].Body
	}

	responseMsg(w, 200, msgs)
}

func (cfg apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {

	chirpID := r.PathValue("chirpID")
	uuidChirp, err := uuid.Parse(chirpID)
	if err != nil {
		log.Printf("Failed to parse string uuid: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	dbChirp, err := cfg.Db.GetChirp(r.Context(), uuidChirp)
	if err != nil {
		log.Printf("Chirp does not exist: %s", err)
		msg := "Chirp does not exist"
		responseError(w, msg, 404)
		return
	}

	type dbChirpJson struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	responseMsg(w, 200, dbChirpJson{
		ID:        dbChirp.ID.String(),
		CreatedAt: dbChirp.CreatedAt.String(),
		UpdatedAt: dbChirp.UpdatedAt.String(),
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID.String(),
	})

}

func (cfg apiConfig) newUser(w http.ResponseWriter, r *http.Request) {

	type client_data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	hash, err := auth.HashPassword(data.Password)
	if err != nil {
		log.Printf("Failed to hash password: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	user, err := cfg.Db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          data.Email,
		HashedPassword: hash,
	})
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

	responseMsg(w, 201, json_user)
	//w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(201)
	//w.Write(json_data)

}

func (cfg apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {

	type loginInfo struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		ExpiresIn int    `json:"expires_in_seconds"`
	}

	var creds loginInfo
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&creds)
	if err != nil {
		log.Printf("Failed to decode data: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	dbUser, err := cfg.Db.GetUser(r.Context(), creds.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			msg := "Incorrect email or password"
			responseError(w, msg, 401)
			return
		}

		log.Printf("Failed to retrieve user: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	err = auth.CheckPasswordHash(creds.Password, dbUser.HashedPassword)
	if err != nil {
		msg := "Incorrect email or password"
		responseError(w, msg, 401)
		return
	}

	timeDuration := time.Hour
	if creds.ExpiresIn > 0 && creds.ExpiresIn < 3600 {
		timeDuration = (time.Second * time.Duration(creds.ExpiresIn))
	}

	token, err := auth.MakeJWT(dbUser.ID, cfg.Secret, timeDuration)
	if err != nil {
		log.Printf("Failed to create jwt token")
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	type dbUserJson struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
		Token     string `json:"token"`
	}

	responseMsg(w, 200, dbUserJson{
		ID:        dbUser.ID.String(),
		CreatedAt: dbUser.CreatedAt.String(),
		UpdatedAt: dbUser.UpdatedAt.String(),
		Email:     dbUser.Email,
		Token:     token,
	})
}

func main() {

	//Database connection
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	pf := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database")
	}

	dbQueries := database.New(db)

	mux := http.NewServeMux()
	api_cfg := apiConfig{
		Db:       dbQueries,
		platform: pf,
		Secret:   secret,
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

	// API
	mux.HandleFunc("POST /api/chirps", api_cfg.newChirp)
	mux.HandleFunc("GET /api/chirps", api_cfg.getChirps)
	mux.HandleFunc("POST /api/users", api_cfg.newUser)
	mux.HandleFunc("GET /api/chirps/{chirpID}", api_cfg.getChirp)
	mux.HandleFunc("POST /api/login", api_cfg.handleLogin)
	//mux.HandleFunc("POST /api/chiprs",)
	server := http.Server{}
	server.Handler = mux
	server.Addr = ":8080"

	//Listen on bind address
	server.ListenAndServe()
}
