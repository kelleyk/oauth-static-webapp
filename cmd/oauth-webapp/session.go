package main

import (
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// SessionInfo describes the authenticated user, if any, associated with a session.
type SessionInfo struct {
	// RemoteIP is the address from which the session was created.
	RemoteIP string
	// Randomly-generated string used for CSRF protection.
	OAuthState string
	// Created is the time that the session was created; it is always UTC.
	Created time.Time

	OAuthToken *oauth2.Token
	AuthInfo   *OAuthResponse
}

func NewSessionInfo(r *http.Request) *SessionInfo {
	return &SessionInfo{
		RemoteIP:   remoteIP(r),
		OAuthState: randString(stateStringLength),
		Created:    time.Now().UTC(),
	}
}

// TODO: Unit test: what is returned from NewSessionInfo() is not ValidAuth().

// ValidAuth returns nil iff the user is logged in and their session is still valid.  It returns a descriptive error
// otherwise.
func (si *SessionInfo) ValidAuth(r *http.Request) error {
	switch {
	case si == nil:
		return errors.New("session info is nil")
	case si.OAuthToken == nil:
		return errors.New("no oauth token attached to session")
	case si.AuthInfo == nil:
		return errors.New("no oauth userinfo attached to session")

	case si.AuthInfo.Email == "":
		// TODO: Unexpected/error condition!  This should never happen.
		return errors.New("no authenticated email")
	case remoteIP(r) != si.RemoteIP:
		return errors.New("inetaddr mismatch")
	}

	age := time.Now().UTC().Sub(si.Created)
	switch {
	case age < 0:
		return errors.New("session is from the future")
	case age > sessionLifespan:
		return errors.New("session has expired")
	}

	return nil
}

func init() {
	// N.B.: `github.com/gorilla/sessions` uses `encoding/gob` to serialize custom types.
	gob.Register(&SessionInfo{})
	gob.Register(&OAuthResponse{})
	gob.Register(&oauth2.Token{})
}

func loadSession(r *http.Request) (*sessions.Session, error) {
	// Get a session. Get() always returns a session, even if empty.
	session, err := cookieStore.Get(r, "session-name")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load session from cookie store")
	}

	return session, nil
}

func loadSessionInfo(r *http.Request) (*SessionInfo, error) {
	session, err := loadSession(r)
	if err != nil {
		return nil, err
	}

	// Retrieve information about our session.
	val := session.Values[`i`]
	var ok bool
	si := &SessionInfo{}
	if si, ok = val.(*SessionInfo); !ok {
		return nil, errors.Wrapf(err, "SessionInfo ('i') is not of expected type; raw value is %T %v", val, val)
	}

	return si, nil
}

func saveSessionInfo(w http.ResponseWriter, r *http.Request, si *SessionInfo) error {
	session, err := loadSession(r)
	if err != nil {
		return err
	}

	session.Values[`i`] = si
	if err := session.Save(r, w); err != nil {
		return errors.Wrap(err, "failed to save session")
	}

	return nil
}
