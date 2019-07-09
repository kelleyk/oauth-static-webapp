package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/kelleyk/oauth-static-webapp/content"
)

const (
	readTimeout       = 3 * time.Second
	writeTimeout      = 3 * time.Second
	maxHeaderBytes    = 1 << 20 // N.B>: ~1 MiB
	stateStringLength = 16

	oauthHostedDomain = "kelleyk.net" // Only accept logins from this domain.

	sessionLifespan = 24 * time.Hour
)

var (
	oauthConfig *oauth2.Config

	randRunes = []rune(`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`)

	cookieStore sessions.Store
)

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("fatal error: %v", err)
	}

	if err := serveContent(); err != nil {
		log.Fatalf("fatal error: %v", err)
	}
}

func loadConfig() error {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		// XXX: This is probably an unsafe default.
		baseURL = "http://localhost:8080"
	}

	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return errors.New("environment variables must be set: OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET")
	}

	oauthConfig = &oauth2.Config{
		RedirectURL:  baseURL + "/_oauth/callback",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	return nil
}

func serveContent() error {
	cookieStoreKey, err := base64.StdEncoding.DecodeString(os.Getenv("COOKIE_STORE_KEY"))
	if err != nil {
		return errors.Wrapf(err, "failed to deserialize COOKIE_STORE_KEY")
	}
	if len(cookieStoreKey) != 64 {
		return errors.Wrapf(err, "bad length for COOKIE_STORE_KEY")
	}
	cookieStore = sessions.NewCookieStore(cookieStoreKey)

	servePath := os.Getenv("SERVE_PATH")
	if servePath == "" {
		servePath = "/var/www"
	}

	mux := http.NewServeMux()

	// mux.Handle("/", authRequiredWrapper(http.FileServer(http.Dir(servePath))))
	mux.HandleFunc("/", assetHandler)

	mux.HandleFunc("/_oauth/login", handleOauthLogin) // XXX: Is this actually useful?
	mux.HandleFunc("/_oauth/callback", handleOauthCallback)
	mux.HandleFunc("/_oauth/error", handleOauthError)
	mux.HandleFunc("/_oauth/logout", handleOauthLogout)
	mux.HandleFunc("/_oauth/info", handleOauthInfo)

	s := &http.Server{
		Addr: ":9090", // XXX: make configurable
		// N.B.: http://www.gorillatoolkit.org/pkg/sessions says that we need to wrap our handler with ClearHandler or
		// else we'll leak memory.
		Handler:        context.ClearHandler(mux),
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	if err := s.ListenAndServe(); err != nil {
		return errors.Wrapf(err, "failed to listen and serve")
	}

	return nil
}

// XXX: Copied from sketchy blog.
func assetHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" {
		path = "index.html"
	}

	if data, err := content.Asset(path); err != nil {
		// XXX: Get standard error for status.
		http.Error(w, "Not found", http.StatusNotFound)
		// w.WriteHeader(http.StatusNotFound)
	} else {
		buf := bytes.NewBuffer(data)
		io.Copy(w, buf)
	}
}
