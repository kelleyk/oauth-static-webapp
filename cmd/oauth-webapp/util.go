package main

import (
	"math/rand"
	"net"
	"net/http"
	"strings"
)

func remoteIP(r *http.Request) string {
	// Comma-separated list (with whitespace); first is the client, and subsequent entries are proxies/etc.
	s := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	return net.ParseIP(s).String()
}

func randString(n int) string {
	rr := make([]rune, n)
	for i := range rr {
		rr[i] = randRunes[rand.Intn(len(randRunes))]
	}
	return string(rr)
}
