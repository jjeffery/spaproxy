// Package websession provides a typesafe interface for web sessions.
package websession

import (
	"crypto/sha256"
	"encoding/base32"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/oauth2"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/spaproxy/dynamodbstore"
)

// Config contains the configuration for web sessions.
type Config struct {
	// Name of the session cookie
	CookieName string

	// DynamoDB table name
	TableName string

	// Session is the AWS session
	Session *session.Session

	// Secrets for secure cookie generation.
	Secret         string
	PreviousSecret string

	MaxAge int  // Maximum session age in seconds
	Secure bool // Should cookies be secure
}

// Storage provides access to web sessions.
type Storage struct {
	store      sessions.Store
	cookieName string
}

// NewStorage returns session storage.
func NewStorage(config *Config) (*Storage, error) {
	db := dynamodb.New(config.Session)
	keyPairs := newKeyPairs(config.Secret, config.PreviousSecret)
	store, err := dynamodbstore.NewDynamodbStore(db, keyPairs...)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create dynamodb store")
	}
	store.TableName = config.TableName
	maxAge := config.MaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	store.DefaultMaxAge = maxAge
	store.Options.Secure = config.Secure
	store.Options.MaxAge = maxAge
	store.Options.HttpOnly = true
	// TODO(jpj): add SameSite

	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "session_id"
	}

	storage := &Storage{
		store:      store,
		cookieName: cookieName,
	}
	return storage, nil
}

func newKeyPairs(secrets ...string) [][]byte {
	var keyPairs [][]byte

	for _, secret := range secrets {
		if secret != "" {
			hashKey, encryptKey := newKeyPair(secret)
			keyPairs = append(keyPairs, hashKey, encryptKey)
		}
	}

	return keyPairs
}

// newKeyPair takes a secret and prepares two keys using
// the HKDF key derivation function.
func newKeyPair(secret string) ([]byte, []byte) {
	hash := sha256.New
	kdf := hkdf.New(hash, []byte(secret), nil, nil)

	hashKey := make([]byte, 32)
	encryptKey := make([]byte, 32)
	kdf.Read(hashKey)
	kdf.Read(encryptKey)

	return hashKey, encryptKey
}

// Session provides a typesafe session.
type Session struct {
	sess *sessions.Session
}

// GetSession returns the session associated with the current request.
// If the session cooke is not valid, the response will contain a header
// to delete the cookie.
func (s *Storage) GetSession(w http.ResponseWriter, r *http.Request) (*Session, error) {
	sess, err := s.store.Get(r, s.cookieName)
	if err != nil {
		if cookieErr, ok := err.(securecookie.Error); ok {
			// the cookie passed is invalid, attempt to clear it
			if cookieErr.IsDecode() {
				cookie, _ := r.Cookie(s.cookieName)
				if cookie != nil {
					cookie.Expires = time.Unix(0, 0)
					cookie.Value = "(DELETED)"
					http.SetCookie(w, cookie)
				}
			}
		}
		return nil, err
	}
	return &Session{
		sess: sess,
	}, nil
}

// ID is the session unique ID.
func (s *Session) ID() string {
	return s.sess.ID
}

// SetExpires sets the time the session expires.
func (s *Session) SetExpires(d time.Duration) *Session {
	s.sess.Options.MaxAge = int(d / time.Second)
	return s
}

// IsValid returns true if the session has not expired.
func (s *Session) IsValid() bool {
	if s == nil || s.sess == nil {
		return false
	}
	text, _ := s.sess.Values["access_token"].(string)
	return text != ""
}

// Token returns the oauth2 tokens associated with the session,
// or nil if there are not tokens.
func (s *Session) Token() *oauth2.Token {
	var tok oauth2.Token
	if tok.AccessToken, _ = s.sess.Values["access_token"].(string); tok.AccessToken == "" {
		return nil
	}
	tok.RefreshToken, _ = s.sess.Values["refresh_token"].(string)
	tok.TokenType, _ = s.sess.Values["token_type"].(string)
	expiry, _ := s.sess.Values["expiry"].(string)
	tok.Expiry, _ = time.Parse(time.RFC3339, expiry)
	return &tok
}

// IDToken returns the ID token, if it exists.
// The ID token is not part of the oauth2.Token type,
// but is supplied by AWS Cognito.
func (s *Session) IDToken() string {
	text, _ := s.sess.Values["id_token"].(string)
	return text
}

// SetToken sets the oauth2 token associated with the session.
func (s *Session) SetToken(tok *oauth2.Token) *Session {
	if tok == nil {
		for _, k := range []string{"access_token", "token_type", "expiry", "refresh_token", "id_token"} {
			delete(s.sess.Values, k)
		}
	} else {
		s.sess.Values["access_token"] = tok.AccessToken
		s.sess.Values["token_type"] = tok.TokenType
		s.sess.Values["expiry"] = tok.Expiry.Format(time.RFC3339)
		s.sess.Values["refresh_token"] = tok.RefreshToken
		if idToken, ok := tok.Extra("id_token").(string); ok && idToken != "" {
			s.sess.Values["id_token"] = idToken
		} else {
			delete(s.sess.Values, "id_token")
		}
	}
	return s
}

// RequestURI returns the path requested prior to authentication.
func (s *Session) RequestURI() string {
	p, _ := s.sess.Values["uri"].(string)
	return p
}

// SetRequestURI sets the path requested prior to authentication.
func (s *Session) SetRequestURI(uri string) *Session {
	if uri == "" {
		delete(s.sess.Values, "uri")
	} else {
		s.sess.Values["uri"] = uri
	}
	return s
}

// Nonce returns a random nonce associated with the session.
// Used for verifying oauth2 exchanges.
func (s *Session) Nonce() string {
	nonce, _ := s.sess.Values["nonce"].(string)
	if nonce == "" {
		nonce = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(5)), "=")
		s.sess.Values["nonce"] = nonce
	}
	return nonce
}

// Delete the existing session and clear out details. Use for logging out.
func (s *Session) Delete(w http.ResponseWriter, r *http.Request) {
	if s.sess.ID != "" {
		maxAge := s.sess.Options.MaxAge
		s.SetToken(nil)
		s.sess.Options.MaxAge = -1
		s.Save(w, r)
		s.sess.Options.MaxAge = maxAge
	}
	s.Clear()
}

// Clear out the session details, but leave the old session untouched.
func (s *Session) Clear() {
	s.sess.ID = ""
	s.sess.Values = make(map[interface{}]interface{})
}

// Save the session to persistent storage.
func (s *Session) Save(w http.ResponseWriter, r *http.Request) error {
	if err := s.sess.Save(r, w); err != nil {
		return errors.Wrap(err, "cannot save session")
	}
	return nil
}
