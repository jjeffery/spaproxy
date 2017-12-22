package dynamodbstore

import (
	"encoding/base32"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

// DefaultSessionExpire expiry time in seconds for cookies/dynamodb keys to expire
const DefaultSessionExpire = 86400

// DefaultTableName default dynamodb session table name
const DefaultTableName = "SessionTable"

var sessionExpire = DefaultSessionExpire

type dynamodbSession struct {
	ID         string                 `dynamodbav:"id"`
	Values     map[string]interface{} `dynamodbav:"values"`
	Expiration int64                  `dynamodbav:"expiration_time"`
}

func newDynamodbSession(session *sessions.Session) (*dynamodbSession, error) {
	m := make(map[string]interface{}, len(session.Values))
	for k, v := range session.Values {
		ks, ok := k.(string)
		if !ok {
			return nil, errors.New("Non-string key value, cannot serialize session")
		}
		m[ks] = v
	}

	return &dynamodbSession{
		ID:         session.ID,
		Values:     m,
		Expiration: time.Now().Unix() + int64(session.Options.MaxAge),
	}, nil
}

// DynamodbStore stores sessions in a dynamodb backend.
type DynamodbStore struct {
	DB            *dynamodb.DynamoDB
	TableName     string
	Codecs        []securecookie.Codec
	Options       *sessions.Options // default configuration
	DefaultMaxAge int               // default TTL for a MaxAge == 0 session
	maxLength     int
}

var _ sessions.Store = &DynamodbStore{}

// NewDynamodbStore create a new store using the supplied DynamoDB session
func NewDynamodbStore(ddb *dynamodb.DynamoDB, keyPairs ...[]byte) (*DynamodbStore, error) {
	return &DynamodbStore{
		DB:        ddb,
		TableName: DefaultTableName,
		Codecs:    securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: sessionExpire,
		},
		DefaultMaxAge: 60 * 20, // 20 minutes seems like a reasonable default
	}, nil
}

// CreateTable setup a new table for session records using the configured table name
func (s *DynamodbStore) CreateTable(readCapacityUnits, writeCapacityUnits int64) error {
	_, err := s.DB.CreateTable(&dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String("S"),
			},
			// {
			// 	AttributeName: aws.String("expiration_time"),
			// 	AttributeType: aws.String("N"),
			// },
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String(dynamodb.KeyTypeHash),
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(readCapacityUnits),
			WriteCapacityUnits: aws.Int64(writeCapacityUnits),
		},
		TableName: aws.String(s.TableName),
	})

	if err != nil {
		return errors.Wrap(err, "unable to create dynamodb table")
	}

	return nil
}

// DropTable delete table for session records using the configured table name
func (s *DynamodbStore) DropTable() error {
	_, err := s.DB.DeleteTable(&dynamodb.DeleteTableInput{
		TableName: aws.String(s.TableName),
	})
	if err != nil {
		return errors.Wrap(err, "unable to delete dynamodb table")
	}

	return nil
}

// Get returns a session for the given name after adding it to the registry.
//
// See gorilla/sessions FilesystemStore.Get().
func (s *DynamodbStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See gorilla/sessions FilesystemStore.New().
func (s *DynamodbStore) New(r *http.Request, name string) (*sessions.Session, error) {
	var (
		err error
		ok  bool
	)
	session := sessions.NewSession(s, name)
	// make a copy
	options := *s.Options
	session.Options = &options
	session.IsNew = true
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			ok, err = s.load(session)
			session.IsNew = !(err == nil && ok) // not new if no error and data available
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *DynamodbStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge < 0 {
		if err := s.delete(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
	} else {
		// Build an alphanumeric key for the dynamodb store.
		if session.ID == "" {
			session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
		}
		if err := s.save(session); err != nil {
			return err
		}
		encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

// stores the session in dynamodb.
func (s *DynamodbStore) save(session *sessions.Session) error {

	ddbSession, err := newDynamodbSession(session)
	if err != nil {
		return errors.Wrap(err, "failed to encode session")
	}

	item, err := dynamodbattribute.MarshalMap(ddbSession)
	if err != nil {
		return errors.Wrap(err, "failed to convert session data to dynamodbattribute")
	}

	params := &dynamodb.PutItemInput{
		Item:      item,
		TableName: aws.String(s.TableName),
	}

	if _, err := s.DB.PutItem(params); err != nil {
		return errors.Wrap(err, "unable to save session in dynamodb")
	}

	return nil
}

// reads the session from dynamodb.
// returns true if there is a sessoin data in DB
func (s *DynamodbStore) load(session *sessions.Session) (bool, error) {

	params := &dynamodb.QueryInput{
		KeyConditionExpression: aws.String("id = :id"),
		FilterExpression:       aws.String("#exp > :expiration_time"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":id": {
				S: aws.String(session.ID),
			},
			":expiration_time": {
				N: aws.String(strconv.FormatInt(time.Now().Unix(), 10)),
			},
		},
		ExpressionAttributeNames: map[string]*string{
			"#exp": aws.String("expiration_time"),
		},
		TableName:      aws.String(s.TableName),
		ConsistentRead: aws.Bool(true),
	}
	resp, err := s.DB.Query(params)
	if err != nil {
		return false, errors.Wrap(err, "unable to load session from dynamodb")
	}

	if len(resp.Items) == 0 {
		return false, nil
	}

	var ddbSession dynamodbSession

	if err := dynamodbattribute.UnmarshalMap(resp.Items[0], &ddbSession); err != nil {
		return false, errors.Wrap(err, "unable to unmarshall session from dynamodb")
	}

	for k, v := range ddbSession.Values {
		session.Values[k] = v
	}

	return true, nil
}

// removes keys from dynamodb if MaxAge < 0
func (s *DynamodbStore) delete(session *sessions.Session) error {

	params := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(session.ID),
			},
		},
		TableName: aws.String(s.TableName),
	}

	_, err := s.DB.DeleteItem(params)
	if err != nil {
		return errors.Wrap(err, "unable to delete session from dynamodb")
	}

	return nil
}
