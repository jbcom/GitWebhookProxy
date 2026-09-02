package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	httpmock "github.com/jarcoal/httpmock"
	"github.com/jbcom/GitWebhookProxy/pkg/providers"
	"github.com/julienschmidt/httprouter"
)

const (
	proxyGitlabTestSecret = "testSecret"
	proxyGitlabTestEvent  = "testEvent"
	proxyGithubTestSecret = "myGithubTestSecret"
	proxyGithubTestEvent  = "push"
	proxyGitlabTestBody   = "testBody"
	httpBinURL            = "httpbin.org"
	httpBinURLInsecure    = "http://" + httpBinURL
	httpBinURLSecure      = "https://" + httpBinURL
)

var (
	proxyGitlabTestPayload = getGitlabPayload()
)

func getGitlabPayload() []byte {
	payload, _ := ioutil.ReadFile("gitlab_test_payload.json")
	return payload
}

func TestProxy_isPathAllowed(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
	}
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "isPathAllowedWithValidMultipleAllowedPaths",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
			},
			args: args{
				path: "/path2",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithValidOneAllowedPaths",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1"},
				secret:       "secret",
			},
			args: args{
				path: "/path1",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithInvalidPath",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
			},
			args: args{
				path: "/path3",
			},
			want: false,
		},
		{
			name: "isPathAllowedWithEmtpyPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
			},
			args: args{
				path: "",
			},
			want: false,
		},
		{
			name: "isPathAllowedWithAllPathsAllowedAndEmptyPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{},
				secret:       "secret",
			},
			args: args{
				path: "",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithAllPathsAllowedAndRootEmptyPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{},
				secret:       "secret",
			},
			args: args{
				path: "/",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithAllPathsAllowedAndNonEmptyPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{},
				secret:       "secret",
			},
			args: args{
				path: "/path1",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithSomePathsAllowedAndRootPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
			},
			args: args{
				path: "/",
			},
			want: false,
		},
		{
			name: "isPathAllowedWithSomePathsAllowedAndSubPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path4"},
				secret:       "secret",
			},
			args: args{
				path: "/path2/path3",
			},
			want: false,
		},
		{
			name: "isPathAllowedWithSubPathsAllowedAndSubPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2/path3"},
				secret:       "secret",
			},
			args: args{
				path: "/path2/path3",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithSubPathsAllowedAndPathArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2/path3"},
				secret:       "secret",
			},
			args: args{
				path: "/path2",
			},
			want: false,
		},
		{
			name: "isPathAllowedWithAllowedPathTrailingSlashAndNotInArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2/"},
				secret:       "secret",
			},
			args: args{
				path: "/path2",
			},
			want: true,
		},
		{
			name: "isPathAllowedWithSimpleAllowedPathAndTrailingSlashInArg",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
			},
			args: args{
				path: "/path2/",
			},
			want: true,
		},
		{
			name: "isPathAllowedRejectsPrefixAndNestedPaths",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/github-webhook/"},
				secret:       "secret",
			},
			args: args{
				path: "/github-webhook/extra",
			},
			want: false,
		},
		{
			name: "isPathAllowedRejectsLookalikePrefix",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/github-webhook/"},
				secret:       "secret",
			},
			args: args{
				path: "/github-webhook-evil",
			},
			want: false,
		},
		{
			name: "isPathAllowedRejectsWhitespaceLookalike",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{" /github-webhook/ "},
				secret:       "secret",
			},
			args: args{
				path: "/github-webhook ",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
			}
			if got := p.isPathAllowed(tt.args.path); got != tt.want {
				t.Errorf("Proxy.isPathAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func createGitlabHook(tokenHeader string, tokenEvent string, body string, method string) *providers.Hook {
	return &providers.Hook{
		Headers: map[string]string{
			providers.XGitlabToken: tokenHeader,
			providers.XGitlabEvent: tokenEvent,
		},
		Payload:       []byte(body),
		RequestMethod: method,
	}
}

func TestProxy_redirect(t *testing.T) {

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", httpBinURLSecure,
		httpmock.NewStringResponder(200, ``))

	httpmock.RegisterResponder("POST", httpBinURLSecure+"/get",
		httpmock.NewStringResponder(405, ``))

	httpmock.RegisterResponder("POST", httpBinURLSecure+"/post",
		httpmock.NewStringResponder(200, ``))

	httpmock.RegisterResponder("POST", httpBinURLInsecure+"/post",
		httpmock.NewStringResponder(200, ``))

	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
	}
	type args struct {
		hook        *providers.Hook
		redirectURL string
	}
	tests := []struct {
		name               string
		fields             fields
		args               args
		wantStatusCode     int
		wantRedirectedHost string // Only Host not complete URL
		wantErr            bool
	}{
		{
			name: "TestRedirectWithValidValues",
			fields: fields{
				provider:     "gitlab",
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURLSecure + "/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantStatusCode:     http.StatusOK,
			wantRedirectedHost: httpBinURL,
		},
		{
			name: "TestRedirectWithGetUpstream",
			fields: fields{
				provider:     "gitlab",
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURLSecure + "/get",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantStatusCode:     http.StatusMethodNotAllowed,
			wantRedirectedHost: httpBinURL,
		},
		{
			name: "TestRedirectWithEmptyPath",
			fields: fields{
				provider:     "github",
				upstreamURL:  httpBinURLSecure + "/post",
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURLSecure + "/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantStatusCode:     http.StatusOK,
			wantRedirectedHost: httpBinURL,
		},
		{
			name: "TestRedirectWithEmptyPath",
			fields: fields{
				provider:     "github",
				upstreamURL:  httpBinURLSecure + "/post",
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURLSecure + "/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantStatusCode:     http.StatusOK,
			wantRedirectedHost: httpBinURL,
		},
		{
			name: "TestRedirectWithNilHook",
			fields: fields{
				provider:     "github",
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURLSecure + "/post",
				hook:        nil,
			},
			wantErr: true,
		},
		{
			name: "TestRedirectWithInvalidUrl",
			fields: fields{
				provider:     "gitlab",
				upstreamURL:  "https://invalidurl",
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: "https://invalidurl/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantErr: true,
		},
		{
			name: "TestRedirectWithInvalidUrlScheme",
			fields: fields{
				provider:     "gitlab",
				upstreamURL:  "htttpsss://" + httpBinURL,
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: "htttpsss://" + httpBinURL + "/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantErr: true,
		},
		{
			name: "TestRedirectWithUrlWithoutScheme",
			fields: fields{
				provider:     "gitlab",
				upstreamURL:  httpBinURL,
				allowedPaths: []string{},
				secret:       "dummy",
			},
			args: args{
				redirectURL: httpBinURL + "/post",
				hook:        createGitlabHook(proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody, http.MethodPost),
			},
			wantStatusCode:     http.StatusOK,
			wantRedirectedHost: httpBinURL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
			}
			gotResp, gotErrors := p.redirect(tt.args.hook, tt.args.redirectURL)

			if (gotErrors != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", gotErrors, tt.wantErr)
				return
			}

			if tt.wantErr == true && gotErrors != nil {
				return
			}

			if gotResp.StatusCode != tt.wantStatusCode {
				t.Errorf("Proxy.redirect() got StatusCode in response= %v, want %v",
					gotResp.StatusCode, tt.wantStatusCode)
				return
			}

			if gotResp.Request.Host != tt.wantRedirectedHost {
				t.Errorf("Proxy.redirect() got Redirected Host in response= %v, want Redirected Host= %v",
					gotResp.Request.Host, tt.wantRedirectedHost)
				return
			}

		})
	}
}

func createGitlabRequest(method string, path string, tokenHeader string,
	eventHeader string, body string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Add(providers.XGitlabToken, tokenHeader)
	req.Header.Add(providers.XGitlabEvent, eventHeader)
	req.Header.Add(providers.ContentTypeHeader, providers.DefaultContentTypeHeaderValue)
	return req
}

func createGitlabRequestWithPayload(method string, path string, tokenHeader string,
	eventHeader string, body []byte) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Add(providers.XGitlabToken, tokenHeader)
	req.Header.Add(providers.XGitlabEvent, eventHeader)
	req.Header.Add(providers.ContentTypeHeader, providers.DefaultContentTypeHeaderValue)
	return req
}

// A github delivery carrying NO signature header, which is what an unsigned
// probe looks like. The parser treats both signature headers as optional, so
// this reaches `Validate` — where it must be refused.
func createGithubRequestWithoutSignature(method string, path string,
	eventHeader string, body []byte) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Add(providers.XGitHubEvent, eventHeader)
	req.Header.Add(providers.XGitHubDelivery, "test-delivery")
	req.Header.Add(providers.ContentTypeHeader, providers.DefaultContentTypeHeaderValue)
	return req
}

func createSignedGithubRequest(method string, path, eventHeader, secret string, body []byte) *http.Request {
	req := createGithubRequestWithoutSignature(method, path, eventHeader, body)
	req.Header.Set(
		providers.XHubSignature256,
		providers.Signature256Prefix+providers.HashPayload256(secret, body),
	)
	return req
}

func trustTestTLSUpstream(t *testing.T, upstream *httptest.Server) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	trustedTransport := transport.Clone()
	trustedTransport.TLSClientConfig = &tls.Config{RootCAs: roots}
	previousClient := httpClient
	httpClient = &http.Client{Timeout: time.Second * 30, Transport: trustedTransport}
	t.Cleanup(func() { httpClient = previousClient })
}

func TestProxy_proxyRequestInjectsUpstreamBearerOnlyAfterValidHMAC(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"trusted-sender"}}`)

	type upstreamRequest struct {
		authorization string
		rawQuery      string
	}
	received := make(chan upstreamRequest, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- upstreamRequest{
			authorization: r.Header.Get("Authorization"),
			rawQuery:      r.URL.RawQuery,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	trustTestTLSUpstream(t, upstream)

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}
	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		proxyGithubTestSecret,
		payload,
	))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid HMAC status = %d, want %d", rr.Code, http.StatusNoContent)
	}

	select {
	case request := <-received:
		if request.authorization != "Bearer "+upstreamBearerToken {
			t.Fatalf("upstream Authorization = %q, want exact bearer token", request.authorization)
		}
		if request.rawQuery != "" {
			t.Fatalf("upstream query = %q, bearer token must never be query-string transport", request.rawQuery)
		}
	default:
		t.Fatal("valid HMAC delivery did not reach upstream")
	}
}

func TestProxy_proxyRequestRejectsInvalidHMACWithoutBearerOrLeak(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"attacker"}}`)

	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	trustTestTLSUpstream(t, upstream)

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}

	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		"wrong-source-hmac",
		payload,
	))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid HMAC status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if upstreamCalls != 0 {
		t.Fatalf("invalid HMAC reached upstream %d times", upstreamCalls)
	}
	if strings.Contains(rr.Body.String(), upstreamBearerToken) || strings.Contains(logs.String(), upstreamBearerToken) {
		t.Fatal("downstream bearer token leaked through a rejected webhook")
	}
}

func TestProxy_proxyRequestRedactsBearerWhenUpstreamFails(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"trusted-sender"}}`)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+upstreamBearerToken {
			t.Errorf("upstream Authorization = %q, want exact bearer token", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	trustTestTLSUpstream(t, upstream)

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}

	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		proxyGithubTestSecret,
		payload,
	))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("upstream failure status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(rr.Body.String(), upstreamBearerToken) || strings.Contains(logs.String(), upstreamBearerToken) {
		t.Fatal("downstream bearer token leaked through an upstream failure")
	}
}

func TestProxy_proxyRequestRejectsHTTPSRedirectToHTTPBeforeBearerLeaks(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"trusted-sender"}}`)

	redirectDestinationCalls := 0
	redirectDestination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectDestinationCalls++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("HTTP redirect destination received Authorization %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectDestination.Close()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+upstreamBearerToken {
			t.Errorf("initial HTTPS upstream Authorization = %q", got)
		}
		http.Redirect(w, r, redirectDestination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	trustTestTLSUpstream(t, upstream)

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}

	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		proxyGithubTestSecret,
		payload,
	))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("HTTPS to HTTP redirect status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if redirectDestinationCalls != 0 {
		t.Fatalf("HTTP redirect destination received %d requests", redirectDestinationCalls)
	}
	if strings.Contains(rr.Body.String(), upstreamBearerToken) {
		t.Fatal("redirect rejection leaked the downstream bearer token")
	}
}

func TestProxy_proxyRequestAllowsLiteralLoopbackHTTPRedirectForBearerRelay(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"trusted-sender"}}`)

	redirectDestination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+upstreamBearerToken {
			t.Errorf("loopback redirect Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectDestination.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectDestination.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}

	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		proxyGithubTestSecret,
		payload,
	))

	if rr.Code != http.StatusNoContent {
		t.Fatalf("loopback HTTP redirect status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestNewProxyWithUpstreamBearerTokenRequiresWebhookHMAC(t *testing.T) {
	_, err := NewProxyWithUpstreamBearerToken(
		"https://jenkins.example.test",
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		"",
		nil,
		"jenkins-relay-test-token",
	)
	if err == nil {
		t.Fatal("downstream bearer token without a webhook HMAC secret was accepted")
	}
	if strings.Contains(err.Error(), "jenkins-relay-test-token") {
		t.Fatalf("configuration error leaked downstream bearer token: %v", err)
	}
}

func TestNewProxyWithUpstreamBearerTokenRequiresExplicitHTTPS(t *testing.T) {
	for _, upstreamURL := range []string{
		"http://jenkins.example.test",
		"jenkins.example.test",
		"//jenkins.example.test",
		"http://localhost:8080/jenkins",
		"http://127.0.0.1.evil.test:8080/jenkins",
		"http://127.0.0.1:8080/jenkins?token=forbidden",
		"http://127.0.0.1:8080/jenkins#forbidden",
		"http://user@127.0.0.1:8080/jenkins",
	} {
		t.Run(upstreamURL, func(t *testing.T) {
			_, err := NewProxyWithUpstreamBearerToken(
				upstreamURL,
				[]string{"/generic-webhook-trigger/invoke"},
				providers.GithubProviderKind,
				proxyGithubTestSecret,
				nil,
				"jenkins-relay-test-token",
			)
			if err == nil {
				t.Fatalf("non-HTTPS upstream %q was accepted for a bearer relay", upstreamURL)
			}
			if strings.Contains(err.Error(), "jenkins-relay-test-token") || strings.Contains(err.Error(), proxyGithubTestSecret) {
				t.Fatalf("HTTPS validation error leaked a credential: %v", err)
			}
		})
	}
}

func TestNewProxyWithUpstreamBearerTokenRejectsLookalikeRailwayPrivateHosts(t *testing.T) {
	// The private-zone exception is a whole-name match, not a suffix search:
	// a public host that merely contains or ends near the zone, an uppercase
	// spelling, a trailing dot, or a nested label must all stay rejected.
	for _, upstreamURL := range []string{
		"http://ci-jenkins-controller.railway.internal.example.com:8080/jenkins",
		"http://railway.internal:8080/jenkins",
		"http://CI-JENKINS-CONTROLLER.RAILWAY.INTERNAL:8080/jenkins",
		"http://ci-jenkins-controller.railway.internal.:8080/jenkins",
		"http://evil.ci-jenkins-controller.railway.internal:8080/jenkins",
		"http://ci_jenkins.railway.internal:8080/jenkins",
		"http://user@ci-jenkins-controller.railway.internal:8080/jenkins",
		"http://ci-jenkins-controller.railway.internal:8080/jenkins?token=x",
	} {
		t.Run(upstreamURL, func(t *testing.T) {
			_, err := NewProxyWithUpstreamBearerToken(
				upstreamURL,
				[]string{"/generic-webhook-trigger/invoke"},
				providers.GithubProviderKind,
				proxyGithubTestSecret,
				nil,
				"jenkins-relay-test-token",
			)
			if err == nil {
				t.Fatalf("lookalike private upstream %q was accepted for a bearer relay", upstreamURL)
			}
		})
	}
}

func TestNewProxyWithUpstreamBearerTokenAllowsOnlyLiteralLoopbackHTTP(t *testing.T) {
	for _, upstreamURL := range []string{
		"http://127.0.0.1:8080/jenkins",
		"http://[::1]:8080/jenkins",
		// Railway's private networking zone: only resolvable inside one
		// project's WireGuard-encrypted private network.
		"http://ci-jenkins-controller.railway.internal:8080/jenkins",
	} {
		t.Run(upstreamURL, func(t *testing.T) {
			_, err := NewProxyWithUpstreamBearerToken(
				upstreamURL,
				[]string{"/generic-webhook-trigger/invoke"},
				providers.GithubProviderKind,
				proxyGithubTestSecret,
				nil,
				"jenkins-relay-test-token",
			)
			if err != nil {
				t.Fatalf("literal loopback HTTP upstream %q was rejected: %v", upstreamURL, err)
			}
		})
	}
}

func TestNewProxyWithUpstreamBearerTokenRejectsWebhookSecretReuse(t *testing.T) {
	_, err := NewProxyWithUpstreamBearerToken(
		"https://jenkins.example.test",
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		proxyGithubTestSecret,
	)
	if err == nil {
		t.Fatal("webhook HMAC secret reuse as an upstream bearer was accepted")
	}
	if strings.Contains(err.Error(), proxyGithubTestSecret) {
		t.Fatalf("credential-separation error leaked a secret: %v", err)
	}
}

func TestProxy_proxyRequestRejectsUntrustedTLSUpstreamForBearerRelay(t *testing.T) {
	const upstreamBearerToken = "jenkins-relay-test-token"
	payload := []byte(`{"sender":{"login":"trusted-sender"}}`)

	upstreamCalls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	p, err := NewProxyWithUpstreamBearerToken(
		upstream.URL,
		[]string{"/generic-webhook-trigger/invoke"},
		providers.GithubProviderKind,
		proxyGithubTestSecret,
		nil,
		upstreamBearerToken,
	)
	if err != nil {
		t.Fatalf("NewProxyWithUpstreamBearerToken() error = %v", err)
	}

	router := httprouter.New()
	router.POST("/*path", p.proxyRequest)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, createSignedGithubRequest(
		http.MethodPost,
		"/generic-webhook-trigger/invoke",
		proxyGithubTestEvent,
		proxyGithubTestSecret,
		payload,
	))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("untrusted TLS upstream status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if upstreamCalls != 0 {
		t.Fatalf("untrusted TLS upstream received %d bearer relay requests", upstreamCalls)
	}
	if strings.Contains(rr.Body.String(), upstreamBearerToken) {
		t.Fatal("untrusted TLS failure leaked the downstream bearer token")
	}
}

func createRequestWithWrongHeadersKeys(method string, path string, tokenHeader string,
	eventHeader string, body string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Add("X-Wrong-Token", tokenHeader)
	req.Header.Add("X-Wrong-Event", eventHeader)
	return req
}

func createRequestWithoutHeaders(method string, path string, body string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	return req
}

func TestProxy_proxyRequest(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
	}
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantStatusCode int
	}{
		{
			// THE ORDERING BUG, PINNED — AND IT HAS TO BE A GITHUB REQUEST.
			//
			// `isIgnoredUser` has a special case: an EMPTY committer on the
			// github provider is treated as ignored (proxy.go, "committer == ''
			// && p.provider == GithubName"). While the user filter ran BEFORE
			// signature validation, that combination answered 200 to a request
			// the proxy had never authenticated.
			//
			// Measured against the built image with GWP_SECRET set and no
			// signature header at all:
			//
			//     Incoming request from user:
			//     Ignoring request for user:
			//     -> HTTP 200
			//
			// A first attempt at this test used the gitlab provider and passed
			// with the bug reintroduced — gitlab has no empty-committer case,
			// so it never reached the branch. Verified the other way now:
			// swapping the two blocks back in proxy.go fails this test.
			name: "TestProxyRequestRejectsUnsignedGithubRequestWithNoCommitter",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGithubTestSecret,
			},
			args: args{
				request: createGithubRequestWithoutSignature(http.MethodPost, "/post",
					proxyGithubTestEvent, []byte(`{}`)),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithValidValues",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequestWithPayload(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestPayload),
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "TestProxyRequestWithoutConfiguringSecret",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "",
			},
			args: args{
				request: createGitlabRequestWithPayload(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestPayload),
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "TestProxyRequestWithoutSecretHearderInRequest",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequestWithPayload(http.MethodPost, "/post",
					"", proxyGitlabTestEvent, proxyGitlabTestPayload),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithInvalidSecretInHeader",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					"InvalidSecret", proxyGitlabTestEvent, proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithEmptySecretInHeader",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					"", proxyGitlabTestEvent, proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithEmptyEventInHeader",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, "", proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithWrongHeaderKeys",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createRequestWithWrongHeadersKeys(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithoutHeaderKeys",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createRequestWithoutHeaders(http.MethodPost, "/post", proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithUnsupportedUrlPath",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequestWithPayload(http.MethodPost, "/get",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestPayload),
			},
			wantStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name: "TestProxyRequestWithInvalidHttpMethod",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodGet, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestBody),
			},
			wantStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name: "TestProxyRequestWithEmptyBody",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, ""),
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "TestProxyRequestWithNotAllowedPath",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{"/path1"},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name: "TestProxyRequestWithAllowedPath",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{"/post"},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "TestProxyRequestWithInvalidUpstreamUrl",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  "invalidurl",
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "TestProxyRequestWithInvalidProvider",
			fields: fields{
				provider:     "invalid",
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name: "TestProxyRequestWithWrongProviderKind",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       proxyGitlabTestSecret,
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithInvalidSecretInProvider",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "wrong",
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name: "TestProxyRequestWithEmptySecretInProvider",
			fields: fields{
				provider:     providers.GitlabProviderKind,
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				secret:       "",
			},
			args: args{
				request: createGitlabRequest(http.MethodPost, "/post",
					proxyGitlabTestSecret, proxyGitlabTestEvent, proxyGitlabTestSecret),
			},
			wantStatusCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
			}
			router := httprouter.New()
			router.POST("/*path", p.proxyRequest)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, tt.args.request)

			if status := rr.Code; status != tt.wantStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.wantStatusCode)
			}

		})
	}
}

func TestProxy_health(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
	}
	type args struct {
		httpMethod string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantStatusCode int
	}{
		{
			name: "TestHealthCheckGet",
			args: args{
				httpMethod: http.MethodGet,
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "TestHealthCheckPost",
			args: args{
				httpMethod: http.MethodPost,
			},
			wantStatusCode: http.StatusMethodNotAllowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
			}
			router := httprouter.New()
			router.GET("/health", p.health)

			req, err := http.NewRequest(tt.args.httpMethod, "/health", nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.wantStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.wantStatusCode)
			}
		})
	}
}

func TestProxy_Run(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
	}
	type args struct {
		listenAddress string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		//https://stackoverflow.com/questions/46778600/golang-execute-function-after-http-listenandserve
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
			}
			if err := p.Run(tt.args.listenAddress); (err != nil) != tt.wantErr {
				t.Errorf("Proxy.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewProxy(t *testing.T) {
	type args struct {
		upstreamURL  string
		allowedPaths []string
		provider     string
		secret       string
		ignoredUsers []string
	}
	tests := []struct {
		name    string
		args    args
		want    *Proxy
		wantErr bool
	}{
		{
			name: "TestNewProxyWithValidArgs",
			args: args{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
			},
			want: &Proxy{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
			},
		},
		{
			name: "TestNewProxyWithEmptyUpstreamURL",
			args: args{
				upstreamURL:  "",
				allowedPaths: []string{},
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
			},
			wantErr: true,
		},
		{
			name: "TestNewProxyWithNilAllowedPaths",
			args: args{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: nil,
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
			},
			wantErr: true,
		},
		{
			name: "TestNewProxyWithEmptyProvider",
			args: args{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{},
				provider:     "",
				secret:       proxyGitlabTestSecret,
			},
			wantErr: true,
		},
		{
			name: "TestNewProxyWithEmptySecret",
			args: args{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: nil,
				provider:     providers.GitlabProviderKind,
				secret:       "",
			},
			wantErr: true,
		},
		{
			name: "TestNewProxyWithValidArgsAndAllowedPaths",
			args: args{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{"/path1", "/path2"},
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
				ignoredUsers: []string{"user1"},
			},
			want: &Proxy{
				upstreamURL:  httpBinURLSecure,
				allowedPaths: []string{"/path1", "/path2"},
				provider:     providers.GitlabProviderKind,
				secret:       proxyGitlabTestSecret,
				ignoredUsers: []string{"user1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProxy(tt.args.upstreamURL, tt.args.allowedPaths, tt.args.provider, tt.args.secret, tt.args.ignoredUsers)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProxy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_isIgnoredUser(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
		ignoredUsers []string
	}
	type args struct {
		committer string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "TestIsIgnoredUserWithEmptyList",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
				ignoredUsers: []string{},
			},
			args: args{
				committer: "user",
			},
			want: false,
		},
		{
			name: "TestIsIgnoredUserWithValidList",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
				ignoredUsers: []string{"user1", "user2"},
			},
			args: args{
				committer: "user2",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
				ignoredUsers: tt.fields.ignoredUsers,
			}
			if got := p.isIgnoredUser(tt.args.committer); got != tt.want {
				t.Errorf("Proxy.isIgnoredUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_isAllowedUser(t *testing.T) {
	type fields struct {
		provider     string
		upstreamURL  string
		allowedPaths []string
		secret       string
		allowedUsers []string
	}
	type args struct {
		committer string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "TestIsAllowedUserWithEmptyList",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
				allowedUsers: []string{},
			},
			args: args{
				committer: "user",
			},
			want: true,
		},
		{
			name: "TestIsAllowedUserWithValidList",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
				allowedUsers: []string{"user1", "user2"},
			},
			args: args{
				committer: "user2",
			},
			want: true,
		},
		{
			name: "TestIsNotAllowedUserWithValidList",
			fields: fields{
				provider:     providers.GithubProviderKind,
				upstreamURL:  "https://dummyurl.com",
				allowedPaths: []string{"/path1", "/path2"},
				secret:       "secret",
				allowedUsers: []string{"user1", "user2"},
			},
			args: args{
				committer: "user3",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{
				provider:     tt.fields.provider,
				upstreamURL:  tt.fields.upstreamURL,
				allowedPaths: tt.fields.allowedPaths,
				secret:       tt.fields.secret,
				allowedUsers: tt.fields.allowedUsers,
			}
			if got := p.isAllowedUser(tt.args.committer); got != tt.want {
				t.Errorf("Proxy.isAllowedUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
