package main

type OAuthResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"` // URL
	Locale        string `json:"locale"`  // e.g. "en"
	HD            string `json:"hd"`      // e.g. "kelleyk.net"; short for "hosted domain"
}
