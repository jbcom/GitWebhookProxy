package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jbcom/GitWebhookProxy/pkg/parser"
	"github.com/jbcom/GitWebhookProxy/pkg/providers"
	"github.com/jbcom/GitWebhookProxy/pkg/utils"
	"github.com/julienschmidt/httprouter"
)

var (
	// Use the standard transport unchanged so HTTPS upstream connections verify
	// both the certificate chain and hostname. A relay bearer must never cross
	// an unverified TLS connection.
	transport  = http.DefaultTransport.(*http.Transport).Clone()
	httpClient = &http.Client{
		Timeout:   time.Second * 30,
		Transport: transport,
	}
)

type Proxy struct {
	provider            string
	upstreamURL         string
	allowedPaths        []string
	secret              string
	upstreamBearerToken string
	ignoredUsers        []string
	allowedUsers        []string
}

func (p *Proxy) isPathAllowed(path string) bool {
	// All paths allowed
	if len(p.allowedPaths) == 0 {
		return true
	}

	// A configured path represents one webhook endpoint, not a route prefix.
	// Normalise one trailing slash so deployments may configure either form
	// without allowing sibling or nested paths such as /github-webhook/extra.
	for _, configuredPath := range p.allowedPaths {
		allowedPath := strings.TrimSuffix(strings.TrimSpace(configuredPath), "/")
		incomingPath := strings.TrimSuffix(path, "/")
		if allowedPath == incomingPath {
			return true
		}
	}
	return false
}

func (p *Proxy) isIgnoredUser(committer string) bool {
	if len(p.ignoredUsers) > 0 {
		if exists, _ := utils.InArray(p.ignoredUsers, committer); exists {
			return true
		}
	}

	if committer == "" && p.provider == providers.GithubName {
		return true
	}

	return false
}

func (p *Proxy) isAllowedUser(committer string) bool {
	if len(p.allowedUsers) > 0 {
		if exists, _ := utils.InArray(p.allowedUsers, committer); exists {
			return true
		}

		return false
	}

	return true
}

func (p *Proxy) redirect(hook *providers.Hook, redirectURL string) (*http.Response, error) {
	return p.redirectAuthenticated(hook, redirectURL, "")
}

// redirectAuthenticated forwards a delivery only after proxyRequest has
// verified its provider signature. The downstream bearer is deliberately not
// derived from, or shared with, the provider webhook HMAC secret.
func (p *Proxy) redirectAuthenticated(hook *providers.Hook, redirectURL, bearerToken string) (*http.Response, error) {
	if hook == nil {
		return nil, errors.New("Cannot redirect with nil Hook")
	}

	// Parse url to check validity
	url, err := url.Parse(redirectURL)
	if err != nil {
		return nil, err
	}

	// Assign default scheme as http if not specified
	if url.Scheme == "" {
		url.Scheme = "http"
	}

	// Create Redirect request
	req, err := http.NewRequest(hook.RequestMethod, url.String(), bytes.NewBuffer(hook.Payload))

	if err != nil {
		return nil, err
	}

	// Set Headers from hook
	for key, value := range hook.Headers {
		req.Header.Add(key, value)
	}
	if bearerToken != "" {
		// Set rather than Add so an untrusted inbound Authorization value cannot
		// survive parser changes and take precedence at the upstream.
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	return httpClient.Do(req)

}

func (p *Proxy) proxyRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	redirectURL := p.upstreamURL + r.URL.Path

	if r.URL.RawQuery != "" {
		redirectURL += "?" + r.URL.RawQuery
	}

	log.Printf("Proxying Request from '%s', to upstream '%s'\n", r.URL, redirectURL)

	if !p.isPathAllowed(r.URL.Path) {
		log.Printf("Not allowed to proxy path: '%s'", r.URL.Path)
		http.Error(w, "Not allowed to proxy path: '"+r.URL.Path+"'", http.StatusForbidden)
		return
	}

	provider, err := providers.NewProvider(p.provider, p.secret)
	if err != nil {
		log.Printf("Error creating provider: %s", err)
		http.Error(w, "Error creating Provider", http.StatusInternalServerError)
		return
	}

	hook, err := parser.Parse(r, provider)
	if err != nil {
		log.Printf("Error Parsing Hook: %s", err)
		http.Error(w, "Error parsing Hook: "+err.Error(), http.StatusBadRequest)
		return
	}

	// SIGNATURE FIRST. AUTHORISATION SECOND. THIS ORDER WAS THE OTHER WAY AROUND
	// AND THAT WAS A HOLE.
	//
	// The user filter used to run first and answer 200 to anything it decided
	// to ignore — before the signature was ever checked. So an UNSIGNED request
	// whose payload carried no committer, or a committer on the ignore list,
	// got a 200 from a proxy that had not authenticated it at all.
	//
	// Measured against the built image, `GWP_SECRET` set, no signature header
	// whatsoever:
	//
	//     Incoming request from user:
	//     Ignoring request for user:
	//     -> HTTP 200
	//
	// It never reached upstream, so it was not a forwarding bug. It was worse
	// in a quieter way: a public endpoint reporting success for a request it
	// had refused to authenticate, which is exactly what a probe looks for.
	//
	// The committer name is read from the PAYLOAD, and the payload is only
	// trustworthy after the signature says so. Deciding anything on it first —
	// including deciding to ignore it — is deciding on attacker-supplied data.
	validated := len(strings.TrimSpace(p.secret)) > 0
	if validated && !provider.Validate(*hook) {
		log.Printf("Error Validating Hook for '%s'", r.URL)
		http.Error(w, "Error validating Hook", http.StatusBadRequest)
		return
	}

	committer := provider.GetCommitter(*hook)
	log.Printf("Incoming request from user: %s", committer)
	if p.isIgnoredUser(committer) || (!p.isAllowedUser(committer)) {
		log.Printf("Ignoring request for user: %s", committer)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Ignoring request for user: %s", committer)))
		return
	}

	var resp *http.Response
	var errs error
	if validated {
		// This is the sole injection point for the relay-to-upstream credential.
		// It is reached only after a configured provider HMAC validates.
		resp, errs = p.redirectAuthenticated(hook, redirectURL, p.upstreamBearerToken)
	} else {
		resp, errs = p.redirect(hook, redirectURL)
	}
	if errs != nil {
		log.Printf("Error Redirecting '%s' to upstream '%s': %s\n", r.URL, redirectURL, errs)
		http.Error(w, "Error Redirecting '"+r.URL.String()+"' to upstream '"+redirectURL+"'", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Error Redirecting '%s' to upstream '%s', Upstream Redirect Status: %s\n", r.URL, redirectURL, resp.Status)
		http.Error(w, "Error Redirecting '"+r.URL.String()+"' to upstream '"+redirectURL+"' Upstream Redirect Status:"+resp.Status, resp.StatusCode)
		return
	}

	log.Printf("Redirected incomming request '%s' to '%s' with Response: '%s'\n",
		r.URL, redirectURL, resp.Status)

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error Reading upstream '%s' response body\n", r.URL)
		http.Error(w, "Error Reading upstream '"+redirectURL+"' Response body", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(responseBody)
}

// Health Check Endpoint
func (p *Proxy) health(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	w.WriteHeader(200)
	w.Write([]byte("I'm Healthy and I know it! ;) "))
}

// Run starts Proxy server
func (p *Proxy) Run(listenAddress string) error {
	if len(strings.TrimSpace(listenAddress)) == 0 {
		panic("Cannot create Proxy with empty listenAddress")
	}

	router := httprouter.New()
	router.GET("/health", p.health)
	router.POST("/*path", p.proxyRequest)

	log.Printf("Listening at: %s", listenAddress)
	return http.ListenAndServe(listenAddress, router)
}

func NewProxy(upstreamURL string, allowedPaths []string,
	provider string, secret string, ignoredUsers []string) (*Proxy, error) {
	return newProxy(upstreamURL, allowedPaths, provider, secret, ignoredUsers, "")
}

// NewProxyWithUpstreamBearerToken creates a proxy which presents a separate
// bearer token to its upstream only after a provider HMAC validates. The
// original NewProxy API intentionally remains available for relays which do
// not need downstream authentication.
func NewProxyWithUpstreamBearerToken(upstreamURL string, allowedPaths []string,
	provider string, secret string, ignoredUsers []string, upstreamBearerToken string) (*Proxy, error) {
	return newProxy(upstreamURL, allowedPaths, provider, secret, ignoredUsers, upstreamBearerToken)
}

func newProxy(upstreamURL string, allowedPaths []string,
	provider string, secret string, ignoredUsers []string, upstreamBearerToken string) (*Proxy, error) {
	// Validate Params
	if len(strings.TrimSpace(upstreamURL)) == 0 {
		return nil, errors.New("Cannot create Proxy with empty upstreamURL")
	}
	if len(strings.TrimSpace(provider)) == 0 {
		return nil, errors.New("Cannot create Proxy with empty provider")
	}
	if allowedPaths == nil {
		return nil, errors.New("Cannot create Proxy with nil allowedPaths")
	}
	if strings.TrimSpace(upstreamBearerToken) != "" && strings.TrimSpace(secret) == "" {
		return nil, errors.New("Cannot configure upstream bearer token without a webhook secret")
	}
	if strings.TrimSpace(upstreamBearerToken) != "" {
		parsedUpstreamURL, err := url.Parse(upstreamURL)
		if err != nil || !isBearerSafeUpstream(parsedUpstreamURL) {
			return nil, errors.New("Upstream bearer token requires HTTPS or literal loopback HTTP")
		}
		if upstreamBearerToken == secret {
			return nil, errors.New("Upstream bearer token must differ from the webhook secret")
		}
	}

	return &Proxy{
		provider:            provider,
		upstreamURL:         upstreamURL,
		allowedPaths:        allowedPaths,
		secret:              secret,
		upstreamBearerToken: upstreamBearerToken,
		ignoredUsers:        ignoredUsers,
	}, nil
}

func isBearerSafeUpstream(upstreamURL *url.URL) bool {
	if upstreamURL == nil || upstreamURL.Host == "" || upstreamURL.User != nil ||
		upstreamURL.RawQuery != "" || upstreamURL.Fragment != "" {
		return false
	}
	if upstreamURL.Scheme == "https" {
		return true
	}
	// The only HTTP exception is a literal loopback destination, used when a
	// hardened relay and its private upstream share one process namespace. It
	// cannot cross a network, and no alternate spelling or URL decoration is
	// accepted.
	return upstreamURL.Scheme == "http" &&
		(upstreamURL.Hostname() == "127.0.0.1" || upstreamURL.Hostname() == "::1")
}
