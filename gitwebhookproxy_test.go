package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainMissingUpstreamURLExitsCleanly(t *testing.T) {
	if os.Getenv("GITWEBHOOKPROXY_TEST_MISSING_UPSTREAM") == "1" {
		os.Args = []string{os.Args[0]}
		main()
		return
	}

	command := exec.Command(os.Args[0], "-test.run=TestMainMissingUpstreamURLExitsCleanly")
	command.Env = environmentWithoutWebhookProxyConfiguration()
	command.Env = append(command.Env, "GITWEBHOOKPROXY_TEST_MISSING_UPSTREAM=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("main succeeded without the required upstreamURL flag")
	}

	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 2 {
		t.Fatalf("main exit code = %v, want 2; output: %s", err, output)
	}

	outputText := string(output)
	if !strings.Contains(outputText, "required flag 'upstreamURL' not specified") {
		t.Fatalf("missing configuration error in output: %s", output)
	}
	if strings.Contains(strings.ToLower(outputText), "panic") {
		t.Fatalf("configuration failure must not panic: %s", output)
	}
}

func environmentWithoutWebhookProxyConfiguration() []string {
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GWP_") {
			environment = append(environment, entry)
		}
	}

	return environment
}
