//go:build desktop

package main

import (
	"strings"
	"testing"
)

// The gateway names the cookie and this application builds a regular
// expression out of that name. Both go into the page as JavaScript literals,
// so a quote in either would end the string it sits in and leave a broken
// script in a window somebody is signing into.
func TestTheCaptureScriptQuotesWhatCameFromTheGateway(t *testing.T) {
	js := captureScript(`acSaml"v2'Token`, `http://127.0.0.1:1/a"b`)

	if strings.Contains(js, `"acSaml"v2`) {
		t.Errorf("the cookie name was not quoted:\n%s", js)
	}
	if !strings.Contains(js, `"acSaml\"v2'Token"`) {
		t.Errorf("the cookie name is not a JavaScript literal:\n%s", js)
	}
	if !strings.Contains(js, `"http://127.0.0.1:1/a\"b"`) {
		t.Errorf("the callback address is not a JavaScript literal:\n%s", js)
	}
}

// It has to do nothing at all until the cookie appears. Identity provider
// pages come and go underneath it, and one that reached for anything else on
// them would be reading a corporate login rather than the one value it is
// there for.
func TestTheCaptureScriptOnlyReadsTheOneCookie(t *testing.T) {
	js := captureScript("acSamlv2Token", "http://127.0.0.1:1/abc")

	if !strings.Contains(js, "document.cookie.match(re)") {
		t.Errorf("it does not read the cookie by name:\n%s", js)
	}
	if !strings.Contains(js, "if(!m||!m[1])return;") {
		t.Errorf("it acts before the cookie is there:\n%s", js)
	}
	for _, reach := range []string{"document.forms", "querySelector", "innerHTML", "localStorage"} {
		if strings.Contains(js, reach) {
			t.Errorf("it touches %q, which is not the value it is here for:\n%s", reach, js)
		}
	}
}

// A navigation, not a request: a page on the gateway's origin is not allowed
// to make requests to loopback and does not need to be.
func TestTheAnswerGoesBackAsANavigation(t *testing.T) {
	js := captureScript("acSamlv2Token", "http://127.0.0.1:1/abc")
	if !strings.Contains(js, "location.replace(") {
		t.Errorf("the answer is not sent by navigating:\n%s", js)
	}
	if strings.Contains(js, "fetch(") || strings.Contains(js, "XMLHttpRequest") {
		t.Errorf("the answer is sent by a request, which loopback will refuse:\n%s", js)
	}
	if !strings.Contains(js, "encodeURIComponent(m[1])") {
		t.Errorf("the value is not escaped into the address:\n%s", js)
	}
}

// The window starts on a page of this application's own, because on Windows
// the injected script is only installed for a window that starts from HTML.
// That page exists only to leave, and a sign-on address is a query string
// full of things that end an attribute.
func TestTheBootstrapPageEscapesTheSignOnAddress(t *testing.T) {
	target := `https://vpn.example/+CSCOE+/saml/sp/login?ctx=1&a="><script>x</script>`
	page := bootstrapHTML("tunnel — sign in", target)

	if strings.Contains(page, "<script>x</script>") {
		t.Errorf("the address was written into the page unescaped:\n%s", page)
	}
	if !strings.Contains(page, `content="0;url=https://vpn.example/+CSCOE+/saml/sp/login?ctx=1&amp;a=`) {
		t.Errorf("the redirect does not carry the address:\n%s", page)
	}
	// The scripted redirect is a JavaScript literal inside a <script> block,
	// so the one sequence that must not survive it is a closing script tag.
	// Encoding as JSON escapes those to \u003c and \u003e, which is what
	// stops an address ending the element it is written into.
	if strings.Contains(page, `location.replace("https://vpn.example`) &&
		strings.Contains(page, `x</script>");`) {
		t.Errorf("the scripted redirect can be ended by the address:\n%s", page)
	}
	if !strings.Contains(page, `location.replace("https://vpn.example/+CSCOE+/saml/sp/login?ctx=1\u0026a=`) {
		t.Errorf("the scripted redirect does not carry the address:\n%s", page)
	}
}
