package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func handleOauthCallback(w http.ResponseWriter, r *http.Request) {
	if err := handleOauthCallbackC(w, r); err != nil {
		log.Printf("error during oauth callback: %v", err)
		http.Error(w, "error during oauth callback: "+err.Error(), http.StatusInternalServerError) // XXX: Don't print sensitive error messages when not in debug mode!
		// http.Redirect(w, r, "/_oauth/error", http.StatusTemporaryRedirect)
		return
	}
}

func handleOauthCallbackC(w http.ResponseWriter, r *http.Request) error {
	log.Printf("oauth callback: @ 0")

	si, err := loadSessionInfo(r)
	if err != nil {
		return errors.Wrap(err, "failed to load session info")
	}

	////////////////////////////////
	// Validate callback
	////////////////////////////////
	log.Printf("oauth callback: @ 1")
	// fmt.Printf("*** oauth callback request:\n%v\n", r)
	// fmt.Printf("*** si:\n%v\n", si)

	// XXX: Store OAuth `token`/etc.?
	// XXX: Check `hd`

	state := r.FormValue("state")
	switch {
	case len(si.OAuthState) != stateStringLength:
		fmt.Printf("err cond A\n")
		return errors.Wrap(err, "bad length for state string stored in session")
	case si.OAuthState != state:
		fmt.Printf("err cond B\n")
		log.Printf("stored oauth state: %v", si.OAuthState)
		log.Printf("request contains oauth state: %v", state)
		return errors.Wrap(err, "invalid state returned with response; CSRF attempt?")
	}

	////////////////////////////////
	// Perform exchange; get token.
	////////////////////////////////
	log.Printf("oauth callback: @ 2")

	code := r.FormValue("code")
	token, err := oauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return errors.Wrap(err, "code exchange failed")
	}

	si.OAuthToken = token

	////////////////////////////////
	// Use OAuth token to get user information.
	////////////////////////////////
	log.Printf("oauth callback: @ 3")

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close response body while calling back to Google: %v", err)
			return
		}
	}()

	if resp.StatusCode != 200 {
		return errors.Wrap(err, "got error status from Google endpoint")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read body of response from Google endpoint")
	}

	oauthResponse := &OAuthResponse{}
	if err := json.Unmarshal(body, oauthResponse); err != nil {
		return errors.Wrap(err, "failed to unmarshal JSON response")
	}

	// if err := si.Authenticate(r, oauthResponse); err != nil {
	// 	return errors.Wrap(err, "failed to authenticate session")
	// }
	si.AuthInfo = oauthResponse

	// Success!  Save the updated session object and redirect the user.
	// TODO: Remember the URL they originally wanted instead of sending them to "/"?
	if err := saveSessionInfo(w, r, si); err != nil {
		return errors.Wrap(err, "failed to save session")
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	log.Printf("oauth callback: @ END")
	return nil
}

func handleOauthError(w http.ResponseWriter, r *http.Request) {
	s := "An error occurred while authenticating you.  Please try again, and ask for help in #it-support if the issue persists."

	if _, err := io.WriteString(w, s); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func handleLoginPrompt(w http.ResponseWriter, r *http.Request) {
	s := "You need to log in!"

	if _, err := io.WriteString(w, s); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func handleOauthInfo(w http.ResponseWriter, r *http.Request) {
	si, err := loadSessionInfo(r)
	if err != nil {
		http.Error(w, "failed to load session", http.StatusInternalServerError)
		return
	}

	s, err := json.Marshal(si)

	if _, err := io.WriteString(w, "session info:\n"+string(s)); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func handleOauthLogout(w http.ResponseWriter, r *http.Request) {
	// Get a session. Get() always returns a session, even if empty.
	session, err := cookieStore.Get(r, "session-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	delete(session.Values, `i`)
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s := `Okay, you're logged out.  [<a href="/">home</a>]`
	w.WriteHeader(http.StatusOK) // w.Write should do this automatically anyhow.
	if _, err := io.WriteString(w, s); err != nil {
		log.Printf("error writing response: %v", err)
	}
}

func handleOauthLogin(w http.ResponseWriter, r *http.Request) {

	// Okay, so we aren't logged in: generate a new session (and OAuth `state`) and ask the user to authenticate.
	// Save the new session before we write to the response/return from the handler (since it'll be returned as a
	// new cookie in a header).
	si := NewSessionInfo(r)
	si.OAuthState = randString(stateStringLength)
	log.Printf("generated oauth state: %v", si.OAuthState)
	if err := saveSessionInfo(w, r, si); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Providing the hosted domain ("hd") parameter here tells Google that we're mostly interested in credentials from
	// this domain.
	// url := oauthConfig.AuthCodeURL(si.OAuthState, oauth2.SetAuthURLParam("hd", oauthHostedDomain))
	url := oauthConfig.AuthCodeURL(si.OAuthState)
	log.Printf("sending user to oauth endpoint: %v\n", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
