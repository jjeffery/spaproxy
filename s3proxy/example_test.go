package s3proxy_test

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/jjeffery/spaproxy/s3proxy"
)

func Example() {
	// proxy all content from the bucket
	// which is in the default AWS region
	h1 := s3proxy.New("bucket-1")

	// AWS session with default credentials but
	// override for the AWS Sydney region.
	sess := session.New(&aws.Config{
		Region: aws.String("ap-southeast-2"),
	})

	// Proxy for bucket "assets-bucket" in the
	// AWS Sydney region. Serves all requests
	// starting with "/assets" from the "assets"
	// folder in the bucket. Everything else is
	// handled by the h1 bucket.
	h2 := s3proxy.New("assets-bucket",
		s3proxy.WithAWSSession(sess),
		s3proxy.StripPath("/assets"),
		s3proxy.WithKeyPrefix("assets"),
		s3proxy.WhenNotFound(h1))

	http.ListenAndServe(":8080", h2)
}
