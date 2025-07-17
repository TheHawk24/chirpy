package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
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
	PolkaAPIKey    string
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

func (cfg *apiConfig) newChirp(w http.ResponseWriter, r *http.Request) {

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

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

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

	authorID := uuid.Nil
	authorIDstr := r.URL.Query().Get("author_id")

	msgs := make([]msgOK, 0)

	if authorIDstr != "" {
		authorID, err = uuid.Parse(authorIDstr)
		if err != nil {
			log.Printf("Failed to parse UUID: %s", err)
			msg := "Something went wrong"
			responseError(w, msg, http.StatusInternalServerError)
			return
		}
	}

	for _, dbChirp := range chirps {
		if authorID != uuid.Nil && authorID != dbChirp.UserID {
			continue
		}

		var msg msgOK
		msg.ID = dbChirp.ID.String()
		msg.CreatedAt = dbChirp.CreatedAt.String()
		msg.UpdatedAt = dbChirp.UpdatedAt.String()
		msg.UserID = dbChirp.UserID.String()
		msg.Body = dbChirp.Body
		msgs = append(msgs, msg)

	}

	sortMethod := r.URL.Query().Get("sort")
	if sortMethod == "desc" {
		sort.Slice(msgs, func(i, j int) bool {
			layout := "2006-01-02 15:04:05.99999 -0700 -0700"
			value1, _ := time.Parse(layout, msgs[i].CreatedAt)
			value2, _ := time.Parse(layout, msgs[j].CreatedAt)
			return value1.After(value2)
		})
	}

	responseMsg(w, 200, msgs)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {

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

func (cfg *apiConfig) newUser(w http.ResponseWriter, r *http.Request) {

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
		Id          string `json:"id"`
		Created_at  string `json:"created_at"`
		Updated_at  string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	var json_user user_resp
	json_user.Id = user.ID.String()
	json_user.Created_at = user.CreatedAt.String()
	json_user.Updated_at = user.UpdatedAt.String()
	json_user.Email = user.Email
	json_user.IsChirpyRed = user.IsChirpyRed

	responseMsg(w, 201, json_user)
	//w.Header().Set("Content-Type", "application/json")
	//w.WriteHeader(201)
	//w.Write(json_data)

}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {

	type loginInfo struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	timeDuration := time.Hour * 1

	token, err := auth.MakeJWT(dbUser.ID, cfg.Secret, timeDuration)
	if err != nil {
		log.Printf("Failed to create jwt token")
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	refreshTokeTimeDuration := time.Now().Add(time.Hour * 1440)
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Failed to create refresh token")
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	dbRefreshToken, err := cfg.Db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: refreshTokeTimeDuration,
	})

	if err != nil {
		log.Printf("Failed to create refresh token on database")
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	type dbUserJson struct {
		ID           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
	}

	responseMsg(w, 200, dbUserJson{
		ID:           dbUser.ID.String(),
		CreatedAt:    dbUser.CreatedAt.String(),
		UpdatedAt:    dbUser.UpdatedAt.String(),
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: dbRefreshToken.Token,
		IsChirpyRed:  dbUser.IsChirpyRed,
	})
}

func (cfg *apiConfig) handleRefreshToken(w http.ResponseWriter, r *http.Request) {

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 400)
		return
	}

	tokenUserID, err := cfg.Db.GetUserFromRefreshToken(r.Context(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			msg := "Not Authorized"
			responseError(w, msg, 401)
			return
		}

		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	if !tokenUserID.RevokedAt.Time.IsZero() {
		msg := "Token Revoked"
		responseError(w, msg, 401)
		return
	}

	expiresAt := tokenUserID.ExpiresAt
	if time.Now().After(expiresAt) || time.Now().Equal(expiresAt) {
		msg := "Not Authorized"
		responseError(w, msg, 401)
		return
	}

	timeDuration := time.Hour * 1
	jwtToken, err := auth.MakeJWT(tokenUserID.UserID, cfg.Secret, timeDuration)
	if err != nil {
		log.Printf("Failed to create jwt token")
		msg := "something went wrong"
		responseError(w, msg, 500)
		return
	}

	type jwtTokenRespJson struct {
		Token string `json:"token"`
	}

	responseMsg(w, 200, jwtTokenRespJson{
		Token: jwtToken,
	})

}

func (cfg *apiConfig) handleRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	err = cfg.Db.UpdateRefreshToken(r.Context(), database.UpdateRefreshTokenParams{
		RevokedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		UpdatedAt: time.Now(),
		Token:     token,
	})

	if err != nil {
		log.Printf("Failed to revoke refresh token")
		msg := "Invalid Token"
		responseError(w, msg, 40)
		return
	}

	responseMsg(w, 204, nil)

}

func (cfg *apiConfig) updateUserInfo(w http.ResponseWriter, r *http.Request) {

	//jwt token
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.Secret)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var body request
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&body)
	if err != nil {
		log.Printf("Failed to decode the data: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	hashedPassword, err := auth.HashPassword(body.Password)
	if err != nil {
		log.Printf("Failed to hash password: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	dbUser, err := cfg.Db.UpdateUser(r.Context(), database.UpdateUserParams{
		Email:          body.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	})

	if err != nil {
		log.Printf("Failed to updated user info: %s", err)
		msg := "Not Authorized"
		responseError(w, msg, 401)
		return
	}

	type dbUserJson struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	responseMsg(w, http.StatusOK, dbUserJson{
		ID:          dbUser.ID.String(),
		Email:       dbUser.Email,
		CreatedAt:   dbUser.CreatedAt.String(),
		UpdatedAt:   dbUser.UpdatedAt.String(),
		IsChirpyRed: dbUser.IsChirpyRed,
	})
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.Secret)
	if err != nil {
		msg := fmt.Sprintf("%s", err)
		responseError(w, msg, 401)
		return
	}

	chirpIDstr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDstr)
	if err != nil {
		log.Printf("Failed to parse string UUID: %s", err)
		msg := "Somethign went wrong"
		responseError(w, msg, 500)
		return
	}

	//Check if chirp exists
	chirp, err := cfg.Db.GetChirp(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Chirp does not exist: %s", err)
			msg := "Chirp does not exist"
			responseError(w, msg, 404)
			return
		}

		log.Printf("Failed to fetch chirp from DB: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	if chirp.UserID != userID {
		msg := "Not allowed"
		responseError(w, msg, 403)
		return
	}

	err = cfg.Db.DeleteChirp(r.Context(), database.DeleteChirpParams{
		ID:     chirpID,
		UserID: userID,
	})

	if err != nil {
		log.Printf("Failed to delete chirp: %s", err)
		msg := "Something went wrong"
		responseError(w, msg, 500)
		return
	}

	responseMsg(w, http.StatusNoContent, nil)
}

func (cfg *apiConfig) upgradeUser(w http.ResponseWriter, r *http.Request) {

	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		responseMsg(w, http.StatusUnauthorized, nil)
		return
	}

	if cfg.PolkaAPIKey != apiKey {
		responseMsg(w, http.StatusUnauthorized, nil)
		return
	}

	type webhook struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	var payment webhook
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&payment)
	if err != nil {
		log.Printf("Failed to decode data from webhook: %s", err)
		responseMsg(w, http.StatusInternalServerError, nil)
		return
	}

	if payment.Event != "user.upgraded" {
		responseMsg(w, http.StatusNoContent, nil)
		return
	}

	if payment.Event == "user.upgraded" {
		parseUUID, err := uuid.Parse(payment.Data.UserID)
		if err != nil {
			log.Printf("Failed to parse UUID: %s", err)
			responseMsg(w, http.StatusInternalServerError, nil)
			return
		}
		_, err = cfg.Db.UpgradeUserChirpyRed(r.Context(), parseUUID)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Could not find user with ID: %s", err)
				responseMsg(w, http.StatusNotFound, nil)
				return
			}
		}

		responseMsg(w, http.StatusNoContent, nil)
		return
	}

}

func main() {

	//Database connection
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	dbURL := os.Getenv("DB_URL")
	pf := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polkaAPIKEY := os.Getenv("POLKA_API_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database")
	}

	dbQueries := database.New(db)

	mux := http.NewServeMux()
	api_cfg := apiConfig{
		Db:          dbQueries,
		platform:    pf,
		Secret:      secret,
		PolkaAPIKey: polkaAPIKEY,
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
	mux.HandleFunc("PUT /api/users", api_cfg.updateUserInfo)
	mux.HandleFunc("GET /api/chirps/{chirpID}", api_cfg.getChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", api_cfg.deleteChirp)
	mux.HandleFunc("POST /api/login", api_cfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", api_cfg.handleRefreshToken)
	mux.HandleFunc("POST /api/revoke", api_cfg.handleRevokeRefreshToken)

	// API webhook
	mux.HandleFunc("POST /api/polka/webhooks", api_cfg.upgradeUser)

	//mux.HandleFunc("POST /api/chiprs",)
	server := http.Server{}
	server.Handler = mux
	server.Addr = ":8080"

	//Listen on bind address
	server.ListenAndServe()
}
