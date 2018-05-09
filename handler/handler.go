// Package handler provides a HTTP handler for the web server.
package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/gorilla/securecookie"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/httpapi"
	"github.com/jjeffery/kv"
	"github.com/jjeffery/spaproxy/amzn"
	"github.com/jjeffery/spaproxy/config"
	"github.com/jjeffery/spaproxy/websession"
	"golang.org/x/oauth2"
)

// New returns the top-level HTTP handler for the web server.
func New() (http.Handler, error) {
	siteURL, err := url.Parse(config.File.SiteURL)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse SiteURL").With(
			"url", config.File.SiteURL,
		)
	}

	s, err := newStuff(siteURL)
	if err != nil {
		return nil, err
	}

	prefix := strings.TrimRight(siteURL.Path, "/")
	addPrefix := func(s string) string {
		if prefix != "" {
			s = path.Join(prefix, s)
		}
		if s == "" || s[0] != '/' {
			s = "/" + s
		}
		return s
	}

	h := chi.NewRouter()
	h.Use(loggerMiddleware)
	h.Method("GET", addPrefix("/oauth2/callback"), http.HandlerFunc(s.handleOauth2Callback))
	h.Method("GET", addPrefix("/logout"), http.HandlerFunc(s.handleOauth2Logout))
	h.Method("GET", addPrefix("/token.json"), http.HandlerFunc(s.handleToken))
	h.Method("GET", addPrefix("/environment.json"), http.HandlerFunc(s.handleEnvironment))
	h.Method("GET", addPrefix("/asset-manifest.json"), http.HandlerFunc(s.handleAssetManifest))
	h.NotFound(s.handleStaticAsset)

	return h, nil
}

type logResponseWriter struct {
	statusCode    int
	w             http.ResponseWriter
	headerWritten bool
}

func (w *logResponseWriter) Header() http.Header {
	return w.w.Header()
}

func (w *logResponseWriter) WriteHeader(status int) {
	if !w.headerWritten {
		w.headerWritten = true
		w.statusCode = status
		w.w.WriteHeader(status)
	}
}

func (w *logResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.headerWritten = true
		w.statusCode = http.StatusOK
	}
	return w.w.Write(b)
}

func loggerMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("start request", kv.List{
			"requestURI", r.RequestURI,
		})
		lw := logResponseWriter{
			w: w,
		}
		h.ServeHTTP(&lw, r)
		log.Println("end request", kv.List{
			"requestURI", r.RequestURI,
			"status", lw.statusCode,
		})
	})
}

type stuff struct {
	store  *websession.Storage
	static http.Handler
	oauth2 oauth2.Config
}

func newStuff(siteURL *url.URL) (*stuff, error) {
	secure := strings.ToLower(siteURL.Scheme) == "https"
	cfg := websession.Config{
		Session:        amzn.Session(),
		TableName:      config.File.Session.Table,
		Secret:         config.File.Session.Secret,
		PreviousSecret: config.File.Session.PreviousSecret,
		Secure:         secure,
	}
	store, err := websession.NewStorage(&cfg)
	if err != nil {
		return nil, err
	}

	// Copy the site URL and modify the path for the callback.
	redirectURL := *siteURL
	redirectURL.Path = path.Join(redirectURL.Path, "oauth2", "callback")

	ocfg := oauth2.Config{
		ClientID:     config.File.OAuth2.ClientID,
		ClientSecret: config.File.OAuth2.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.File.OAuth2.AuthURL,
			TokenURL: config.File.OAuth2.TokenURL,
		},
		RedirectURL: redirectURL.String(),
	}

	stuff := stuff{
		store:  store,
		static: newStaticAssetsHandler(),
		oauth2: ocfg,
	}
	return &stuff, nil
}

func (s *stuff) handleError(w http.ResponseWriter, err error) {
	cause := errors.Cause(err)
	if scerr, ok := cause.(securecookie.Error); ok {
		log.Println("secure cookie error")
		if scerr.IsDecode() {
			log.Println("warn: forbidden:", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	log.Println("error: internal:", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (s *stuff) getSession(w http.ResponseWriter, r *http.Request) (*websession.Session, error) {
	sess, err := s.store.GetSession(w, r)
	if err != nil {
		err = errors.Wrap(err, "cannot get session")
		s.handleError(w, err)
		return nil, err
	}
	return sess, nil
}

func (s *stuff) saveSession(w http.ResponseWriter, r *http.Request, sess *websession.Session) {
	if err := sess.Save(w, r); err != nil {
		log.Println("error: cannot save session:", err)
	}
}

func (s *stuff) handleOauth2Callback(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}

	if sess.IsValid() {
		// already logged in in another tab
		redirectURI := config.File.SiteURL
		log.Println("redirecting", kv.List{
			"url", redirectURI,
		})
		http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	if state != sess.Nonce() {
		log.Println("warn: incorrect oauth2 state", kv.List{
			"expected", sess.Nonce(),
			"actual", state,
			"session", sess.ID(),
		})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token, err := s.oauth2.Exchange(r.Context(), code)
	if err != nil {
		err = errors.Wrap(err, "cannot exchange oauth2 code for token")
		log.Println("warn:", err)
		// todo(jpj): is this the correct error response, probably not
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	redirectURI := sess.RequestURI()
	if redirectURI == "" || strings.Contains(redirectURI, "/oauth2/") {
		redirectURI = config.File.SiteURL
	}
	log.Println("redirecting", kv.List{
		"url", redirectURI,
	})

	sess.Clear()
	sess.SetToken(token)
	sess.Save(w, r)
	http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
}

func (s *stuff) handleOauth2Logout(w http.ResponseWriter, r *http.Request) {
	if isCSRFAttempt(w, r) {
		return
	}

	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}
	sess.Delete(w, r)

	if config.File.OAuth2.LogoutURL != "" {
		u, err := url.Parse(config.File.OAuth2.LogoutURL)
		if err != nil {
			log.Println("warn: cannot parse LogoutURL", kv.List{
				"LogoutURL", config.File.OAuth2.LogoutURL,
				"error", err,
			})
			s.handleError(w, err)
			return
		}
		q := u.Query()
		if q.Get("logout_uri") != "" {
			// When the logout URL contains a "logout_uri" query parameter, then
			// just add the client id and send. This handles the special case for
			// AWS Cognito, for which the "logout_uri" query parameter is significant.
			q.Add("client_id", config.File.OAuth2.ClientID)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
			return
		}
	}

	// This happens if no logout url is provided, or if it does not contain a "logout_uri"
	// query parameter.
	// Take a copy of the oauth2 config so we can modify it by
	// using the logout url as the auth url.
	ocfg := s.oauth2
	if config.File.OAuth2.LogoutURL != "" {
		ocfg.Endpoint.AuthURL = config.File.OAuth2.LogoutURL
	}

	s.redirectToLogin(w, r, sess, &ocfg)
}

func isSameSite(referrer string, siteURL string) bool {
	// perform case-insensitive comparisons
	siteURL = strings.ToLower(siteURL)
	referrer = strings.ToLower(referrer)

	sitePrefix := siteURL
	if !strings.HasSuffix(sitePrefix, "/") {
		sitePrefix += "/"
	}
	return referrer == siteURL ||
		referrer == sitePrefix ||
		strings.HasPrefix(referrer, sitePrefix)
}

func isCSRFAttempt(w http.ResponseWriter, r *http.Request) bool {
	// Check for CSRF from a browser. Note that because CORS is not enabled,
	// any XHR requests should be forbidden.
	// Note that HTTP header has one less "r" than expected: Referer
	// Todo: this logic should be in its own function with its own unit test
	if referrer := r.Header.Get("Referer"); referrer != "" {
		if !isSameSite(referrer, config.File.SiteURL) {
			log.Println("detected CSRF attempt", kv.List{
				"referrer", referrer,
				"requestURI", r.RequestURI,
				"siteURL", config.File.SiteURL,
			})
			http.Error(w, "forbidden", http.StatusForbidden)
			return true
		}
	}
	return false
}

func (s *stuff) handleToken(w http.ResponseWriter, r *http.Request) {
	if isCSRFAttempt(w, r) {
		return
	}

	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}

	token := sess.Token()
	if token == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !token.Valid() {
		log.Println("token is not valid", kv.List{
			"expiry_time", token.Expiry.Format(time.RFC3339),
		})
		tokenSource := s.oauth2.TokenSource(r.Context(), token)
		token, err = tokenSource.Token()
		if err != nil {
			// todo(jpj): is this always an internal error? probably not
			s.handleError(w, errors.Wrap(err, "cannot refresh token"))
			return
		}
		log.Println("new token issued")
		sess.SetToken(token)
		s.saveSession(w, r, sess)
	}

	var response struct {
		IDToken          string `json:"id_token,omitempty"`
		AccessToken      string `json:"access_token"`
		ExpiresInSeconds int64  `json:"expires_in"`
		TokenType        string `json:"token_type"`
		Scope            string `json:"scope,omitempty"`
	}

	response.AccessToken = token.AccessToken
	response.IDToken = sess.IDToken()
	response.TokenType = token.TokenType
	// TODO(jpj): include scope

	// Time to deduct from the expires in seconds. The oauth2 implementation is 10
	// seconnds, if we refresh more than 10 seconds before expiry we will not get
	// a new token. For this reason subtract enough so we will get a new token, but
	// will still have time in the delta period.
	const expiryDeltaSeconds = 9
	response.ExpiresInSeconds = int64(token.Expiry.Sub(time.Now())/time.Second) - expiryDeltaSeconds
	if response.ExpiresInSeconds < 0 {
		response.ExpiresInSeconds = 0
	}

	httpapi.WriteResponse(w, r, response)
}

func (s *stuff) handleEnvironment(w http.ResponseWriter, r *http.Request) {
	if isCSRFAttempt(w, r) {
		return
	}

	// reload the config file, continue if error
	config.Load()

	var b []byte

	if config.File.Environment == nil {
		b = []byte("{}")
	} else {
		var err error
		b, err = json.MarshalIndent(config.File.Environment, "", "  ")
		if err != nil {
			log.Println("error: cannot marshal environment:", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.Write(b)
}

func (s *stuff) handleAssetManifest(w http.ResponseWriter, r *http.Request) {
	// don't publish the asset manifest
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *stuff) handleStaticAsset(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}

	if !sess.IsValid() {
		sess.SetRequestURI(r.RequestURI) // remember the requested URI
		s.redirectToLogin(w, r, sess, nil)
		return
	}

	s.static.ServeHTTP(w, r)
}

func (s *stuff) redirectToLogin(w http.ResponseWriter, r *http.Request, sess *websession.Session, ocfg *oauth2.Config) {
	if ocfg == nil {
		ocfg = &s.oauth2
	}

	authCodeURL := ocfg.AuthCodeURL(sess.Nonce())
	log.Println("redirecting", kv.List{"url", authCodeURL})

	// redirecting to the login page, so set the session
	// lifetime to a long time -- the login page can display
	// for days before someone logs in
	sess.SetExpires(time.Hour * 168)

	s.saveSession(w, r, sess)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}
