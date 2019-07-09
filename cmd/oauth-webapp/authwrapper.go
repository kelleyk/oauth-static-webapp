package main

import (
	"log"
	"net/http"
)

type authRequiredHandler struct {
	h http.Handler
}

var _ http.Handler = (*authRequiredHandler)(nil)

func (arh *authRequiredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := arh.h

	si, err := loadSessionInfo(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Authenticate the user.
	if err := si.ValidAuth(r); err != nil {
		// Redirect the user to log in.
		// handleOauthLogin(w, r)

		log.Printf("session does not have valid auth: %v", err)
		handleLoginPrompt(w, r)
		return
	}

	// Authorize the user.
	if si.AuthInfo.HD != oauthHostedDomain {
		http.Error(w, "You are not authorized to view this resource.  Are you using the correct account?", http.StatusForbidden)
		return
	}

	// Whew.  Finally, call the original handler.
	h.ServeHTTP(w, r)
	return

}

func authRequiredWrapper(h http.Handler) http.Handler {
	return &authRequiredHandler{h: h}
}
