// Package handler provides a HTTP handler for the web server.
package handler

import (
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
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
	h.Use(middleware.Logger)
	h.HandleFunc(addPrefix("/oauth2/callback"), s.handleOauth2Callback)
	h.HandleFunc(addPrefix("/logout"), s.handleOauth2Logout)
	h.HandleFunc(addPrefix("/token.json"), s.handleToken)
	h.NotFound(s.handleStaticAsset)

	return h, nil
}

func loggerMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kvlist := kv.List{
			"url", r.URL,
		}
		log.Println("start request", kvlist)
		h.ServeHTTP(w, r)
		log.Println("end request", kvlist)

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

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	if state != sess.Nonce() {
		log.Println("warn: incorrect oauth2 state", kv.List{
			"expected", sess.Nonce(),
			"actual", state,
			"session", sess.ID(),
		})
		sess.Clear(w, r)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sess.ClearNonce()

	token, err := s.oauth2.Exchange(r.Context(), code)
	if err != nil {
		err = errors.Wrap(err, "cannot exchange oauth2 code for token")
		log.Println("warn:", err)
		sess.Clear(w, r)
		// todo(jpj): is this the correct error response, probably not
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	redirectURI := sess.RequestURI()
	if redirectURI == "" {
		redirectURI = config.File.SiteURL
	}
	log.Println("redirecting", kv.List{
		"url", redirectURI,
	})

	sess.Clear(w, r)
	sess.SetToken(token)
	sess.Save(w, r)
	http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
}

func (s *stuff) handleOauth2Logout(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}
	sess.Clear(w, r)

	// redirecting to the login page, so set the session
	// lifetime to a long time -- the login page can display
	// for days before someone logs in
	sess.SetExpires(time.Hour * 168)

	// take a copy of the oauth2 config so we can modify it by
	// using the logout url as the auth url
	ocfg := s.oauth2
	if config.File.OAuth2.LogoutURL != "" {
		ocfg.Endpoint.AuthURL = config.File.OAuth2.LogoutURL
	}

	authCodeURL := ocfg.AuthCodeURL(sess.NewNonce())
	log.Println("redirecting", kv.List{
		"url", authCodeURL,
	})
	s.saveSession(w, r, sess)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (s *stuff) handleToken(w http.ResponseWriter, r *http.Request) {
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
			s.handleError(w, err)
			return
		}
		sess.SetToken(token)
		s.saveSession(w, r, sess)
	}

	var response struct {
		IDToken          string `json:"idToken,omitempty"`
		AccessToken      string `json:"accessToken"`
		ExpiresInSeconds int64  `json:"expiresInSeconds"`
	}

	response.AccessToken = token.AccessToken
	response.IDToken = sess.IDToken()

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

func (s *stuff) handleStaticAsset(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getSession(w, r)
	if err != nil {
		return
	}

	if !sess.IsValid() {
		sess.Clear(w, r)

		// redirecting to the login page, so set the session
		// lifetime to a long time -- the login page can display
		// for days before someone logs in
		sess.SetExpires(time.Hour * 168)
		sess.SetRequestURI(r.RequestURI) // remember the requested URI
		authCodeURL := s.oauth2.AuthCodeURL(sess.NewNonce())
		log.Println("redirecting", kv.List{
			"url", authCodeURL,
		})
		s.saveSession(w, r, sess)
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
		return
	}

	s.static.ServeHTTP(w, r)
}
