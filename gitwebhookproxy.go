package main

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/jbcom/GitWebhookProxy/pkg/proxy"
	"github.com/namsral/flag"
)

var (
	flagSet       = flag.NewFlagSetWithEnvPrefix(os.Args[0], "GWP", 0)
	listenAddress = flagSet.String("listen", ":8080", "Address on which the proxy listens.")
	upstreamURL   = flagSet.String("upstreamURL", "", "URL to which the proxy requests will be forwarded (required)")
	secret        = flagSet.String("secret", "", "Secret of the Webhook API. If not set validation is not made.")
	provider      = flagSet.String("provider", "github", "Git Provider which generates the Webhook")
	allowedPaths  = flagSet.String("allowedPaths", "", "Comma-Separated String List of allowed paths")
	ignoredUsers  = flagSet.String("ignoredUsers", "", "Comma-Separated String List of users to ignore while proxying Webhook request")
	allowedUsers  = flagSet.String("allowedUser", "", "Comma-Separated String List of users to allow while proxying Webhook request")
)

func validateRequiredFlags() error {
	if len(strings.TrimSpace(*upstreamURL)) == 0 {
		return errors.New("required flag 'upstreamURL' not specified")
	}

	return nil
}

func main() {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(2)
	}
	if err := validateRequiredFlags(); err != nil {
		log.Print(err)
		os.Exit(2)
	}
	lowerProvider := strings.ToLower(*provider)

	// Split Comma-Separated list into an array
	allowedPathsArray := []string{}
	if len(*allowedPaths) > 0 {
		allowedPathsArray = strings.Split(*allowedPaths, ",")
	}

	// Split Comma-Separated list into an array
	ignoredUsersArray := []string{}
	if len(*ignoredUsers) > 0 {
		ignoredUsersArray = strings.Split(*ignoredUsers, ",")
	}

	log.Printf("Stakater Git WebHook Proxy started with provider '%s'\n", lowerProvider)
	// The downstream trigger token is intentionally environment-only. A command
	// line is visible in process listings and often captured by deployment logs.
	upstreamBearerToken := os.Getenv("GWP_UPSTREAMTOKEN")
	p, err := proxy.NewProxyWithUpstreamBearerToken(*upstreamURL, allowedPathsArray, lowerProvider, *secret, ignoredUsersArray, upstreamBearerToken)
	if err != nil {
		log.Fatal(err)
	}

	if err := p.Run(*listenAddress); err != nil {
		log.Fatal(err)
	}

}
