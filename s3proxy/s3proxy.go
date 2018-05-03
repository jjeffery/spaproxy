// Package s3proxy implements a HTTP handler that acts as a
// reverse proxy for static content stored in an AWS S3 bucket.
// It takes an incoming request and retrieves the corresponding
// S3 object, proxying the content back to the client.
package s3proxy

import (
	"io"
	"log"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/kv"
)

var (
	// immutableRE is a regexp that identifies an immutable file.
	immutableRE = regexp.MustCompile(`[.-][0-9a-f]{8,}[.-]`)
)

type proxy struct {
	bucket        string
	keyPrefix     string
	stripPath     string
	session       *session.Session
	s3            *s3.S3
	notFound      http.Handler
	index         string
	hashRE        *regexp.Regexp
	privateCache  bool
	internalError func(http.ResponseWriter, *http.Request, error)
}

// Option is an optional parameter for an S3 proxy.
type Option func(p *proxy)

// New returns a new S3 reverse proxy HTTP handler.
func New(bucket string, opts ...Option) http.Handler {
	p := &proxy{
		bucket:   bucket,
		index:    "index.html",
		notFound: http.HandlerFunc(http.NotFound),
		hashRE:   immutableRE,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	if p.session == nil {
		p.session = session.New()
	}
	p.s3 = s3.New(p.session)
	if p.internalError == nil {
		p.internalError = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
	return p
}

// WithKeyPrefix specifies a prefix that will be prepended
// to the S3 key.
func WithKeyPrefix(keyPrefix string) Option {
	return func(p *proxy) {
		p.keyPrefix = strings.Trim(keyPrefix, "/")
	}
}

// StripPath specifies text that will be stripped from the
// beginning of the HTTP request path.
func StripPath(path string) Option {
	return func(p *proxy) {
		// strip leading and trailing '/' -- they are assumed
		path = strings.Trim(path, "/")
		p.stripPath = path
	}
}

// WithAWSSession specifies the AWS session that will be used
// to interact with AWS S3. If not specified, a session is
// created from environment defaults.
func WithAWSSession(session *session.Session) Option {
	return func(p *proxy) {
		p.session = session
	}
}

// WithIndex specifies the name of the index document.
// The default is "index.html".
func WithIndex(index string) Option {
	return func(p *proxy) {
		p.index = index
	}
}

// WithErrorHandler specifies a function to call when an internal error condition
// occurs. The default implementation sends a 500 status code with the text "internal server error".
func WithErrorHandler(f func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(p *proxy) {
		p.internalError = f
	}
}

// WhenNotFound specifies a handler to invoke when the requested path is not found
// in the S3 bucket. The default is to call the standard libery http.NotFound function.
func WhenNotFound(h http.Handler) Option {
	return func(p *proxy) {
		p.notFound = h
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimLeft(r.URL.Path, "/")

	if p.stripPath != "" {
		if !strings.HasPrefix(key, p.stripPath) {
			// the requested path does not have the strip prefix, so
			// go immediately to not found
			p.notFound.ServeHTTP(w, r)
			return
		}
		key = key[len(p.stripPath):]
	}

	// When true, do not search for an index document if the requested document
	// is not found. Ie, if "static/abc.js" is not found, do not search for
	// "static/abc.js/index.html".
	var doNotSearchForIndexDocument bool

	if key == "" || key == "/" {
		// the root object in the hierarchy means search for the index document
		key = p.index
		doNotSearchForIndexDocument = true
	} else {
		switch strings.ToLower(path.Ext(key)) {
		case ".js", ".html", ".htm", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico":
			// Common file suffixes do not warrant checking if they are a directory.
			// This means that things will not work as expected if you create a directory with
			// a name that has any of these extensions.
			doNotSearchForIndexDocument = true
		}
	}

	if p.keyPrefix != "" {
		key = path.Join(p.keyPrefix, key)
	}

	input := s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	}

	if etag := r.Header.Get("If-None-Match"); etag != "" {
		input.SetIfNoneMatch(etag)
	} else if timestamp := r.Header.Get("If-Modified-Since"); timestamp != "" {
		t, err := http.ParseTime(timestamp)
		// if error parsing the time, don't use it
		if err == nil {
			input.SetIfModifiedSince(t)
		}
	}
	if _range := r.Header.Get("Range"); _range != "" {
		input.SetRange(_range)
	}

	// return here when not found -- attempt to locate index document
retry:
	output, err := p.s3.GetObjectWithContext(r.Context(), &input)
	if err != nil {
		statusCoder, ok := err.(interface{ StatusCode() int })
		if !ok {
			p.internalError(w, r, err)
			return
		}
		statusCode := statusCoder.StatusCode()
		switch statusCode {
		case http.StatusNotModified:
			http.Error(w, "not modified", http.StatusNotModified)
			return
		case http.StatusForbidden, http.StatusNotFound:
			// If the session permission does not include permission to list objects
			// in the bucket, then a 403 will be returned if the object is not found.
			// the reason for this is that without s3:ListObjects permission, the caller
			// is not permitted to tell if an object exists or not.
			//
			// So we interpret a 403 as a 404.
			if statusCode == http.StatusForbidden {
				log.Println("s3 object not found", kv.List{
					"bucket", *input.Bucket,
					"key", *input.Key,
				})
			} else {
				log.Println("s3 object forbidden", kv.List{
					"bucket", *input.Bucket,
					"key", *input.Key,
				})
			}
			if doNotSearchForIndexDocument {
				p.notFound.ServeHTTP(w, r)
				return
			}

			// not found, but could be directory requiring an index
			// document -- append the index document and try again
			key = path.Join(key, p.index)
			doNotSearchForIndexDocument = true
			input.SetKey(key)
			goto retry
		default:
			err = errors.Wrap(err, "cannot get from s3").With(
				"bucket", *input.Bucket,
				"key", *input.Key,
			)
			p.internalError(w, r, err)
			return
		}
	}
	defer output.Body.Close()

	statusCode := http.StatusOK
	if output.ContentRange != nil {
		w.Header().Set("Content-Range", *output.ContentRange)
		statusCode = http.StatusPartialContent
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modfied", (*output.LastModified).Format(time.RFC1123))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if p.hashRE.MatchString(path.Base(key)) {
		// immutable content
		const cacheControl = "max-age=2592000, immutable"
		if p.privateCache {
			w.Header().Set("Cache-Control", "private, "+cacheControl)
		} else {
			w.Header().Set("Cache-Control", cacheControl)
		}
	}
	if contentType := mime.TypeByExtension(path.Ext(key)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(statusCode)

	// no point checking for errors here, because we have already
	// written the header
	io.Copy(w, output.Body)
}
