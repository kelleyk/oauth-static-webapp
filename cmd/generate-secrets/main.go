package main

import (
	"encoding/base64"
	"fmt"

	"github.com/gorilla/securecookie"
)

func main() {
	cookieStoreKey := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64))
	sessionStoreKey := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64))

	fmt.Printf("COOKIE_STORE_KEY=%q\n", cookieStoreKey)
	fmt.Printf("SESSION_STORE_KEY=%q\n", sessionStoreKey)
}
