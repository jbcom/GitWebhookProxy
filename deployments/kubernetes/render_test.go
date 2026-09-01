package kubernetes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBearerRelaySecretIsRenderedForChartAndVanillaDeployments(t *testing.T) {
	files := []string{
		"chart/gitwebhookproxy/templates/deployment.yaml",
		"manifests/deployment.yaml",
		"gitwebhookproxy.yaml",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			source := readRenderContractFile(t, file)
			if !strings.Contains(source, "name: GWP_UPSTREAMTOKEN") {
				t.Fatalf("%s does not expose GWP_UPSTREAMTOKEN", file)
			}
			if !strings.Contains(source, "key: upstreamToken") {
				t.Fatalf("%s does not read the upstreamToken Secret key", file)
			}
		})
	}
}

func TestBearerRelaySecretKeyIsRenderedForChartAndVanillaSecrets(t *testing.T) {
	files := []string{
		"chart/gitwebhookproxy/templates/secret.yaml",
		"manifests/secret.yaml",
		"gitwebhookproxy.yaml",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			source := readRenderContractFile(t, file)
			if !strings.Contains(source, "upstreamToken:") {
				t.Fatalf("%s does not render an upstreamToken Secret key", file)
			}
		})
	}
}

func TestBearerRelayValueIsSecretOnlyAndDocumented(t *testing.T) {
	for _, file := range []string{
		"templates/chart/values.yaml.tmpl",
		"chart/gitwebhookproxy/values.yaml",
		"Readme.md",
	} {
		if !strings.Contains(readRenderContractFile(t, file), "upstreamToken") {
			t.Fatalf("%s does not document/configure upstreamToken", file)
		}
	}

	configMap := readRenderContractFile(t, "manifests/configmap.yaml")
	if strings.Contains(configMap, "upstreamToken") {
		t.Fatal("upstreamToken must not be rendered into the ConfigMap")
	}
}

func readRenderContractFile(t *testing.T, relativePath string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Clean(relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(source)
}
