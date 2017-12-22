// Package amzn provides the session for AWS operations.
package amzn

import (
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws/session"
)

var (
	once sync.Once
	sess *session.Session
)

// Session returns the global AWS session object.
func Session() *session.Session {
	once.Do(func() {
		os.Setenv("AWS_REGION", "ap-southeast-2")
		os.Setenv("AWS_PROFILE", "sp-jjeffery")
		sess = session.New()
	})
	return sess
}
