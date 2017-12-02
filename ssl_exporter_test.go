package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestProbeHandler(t *testing.T) {

	// Test the behaviour of various target URIs
	//    'ok' denotes whether we expect a succesful https connection
	//    'insecure' denotes whether we ignore invalid certs
	cases := []struct {
		uri      string
		ok       bool
		insecure bool
	}{
		// Test against an assumed valid, reachable and functioning HTTPS address
		{uri: "https://google.com", ok: true, insecure: false},
		// Test against a HTTP address
		{uri: "http://google.com", ok: false, insecure: false},
		// Test against an expired certificate when we're rejecting invalid certs
		{uri: "https://expired.badssl.com", ok: false, insecure: false},
		// Test against an expired certificate when we're accepting invalid certs
		{uri: "https://expired.badssl.com", ok: true, insecure: true},
		// Test against a target with no protocol
		{uri: "google.com", ok: false, insecure: false},
		// Test against a string with spaces
		{uri: "with spaces", ok: false, insecure: false},
		// Test against nothing
		{uri: "", ok: false, insecure: false},
	}

	fmt.Println("Note: The error logs in these tests are expected. One of the important tests is that we return the expected body, even in the face of errors.")

	for _, test := range cases {

		uri := "/probe?target=" + test.uri
		req, err := http.NewRequest("GET", uri, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			probeHandler(w, r, test.insecure)
		})

		handler.ServeHTTP(rr, req)

		// We should always return a 200, no matter what
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}

		// Make sure we're getting the ssl_https_connect_success metric back
		successString, err := regexp.MatchString("(ssl_https_connect_success [0-1])", rr.Body.String())
		if err != nil {
			t.Errorf("regexp against response body returned an error w/ %q", uri)
		}
		if !successString {
			t.Errorf("can't find ssl_https_connect_success metric in response body w/ %q", uri)
		}

		// Make sure we're getting the result we expect from ssl_https_connect_success
		ok := strings.Contains(rr.Body.String(), "ssl_https_connect_success 1")
		if test.ok && !ok {
			t.Errorf("expected https connection to succeed but it failed w/ %q", uri)
		}
		if !test.ok && ok {
			t.Errorf("expected https connection to fail but it succeeded w/ %q", uri)
		}

	}
}
