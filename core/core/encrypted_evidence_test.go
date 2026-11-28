package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reportEvidence struct {
	Results []struct {
		Controls []struct {
			ControlID string `json:"controlID"`
			Evidence  []struct {
				Path  string `json:"path"`
				Value string `json:"value"`
			} `json:"evidence"`
		} `json:"controls"`
	} `json:"results"`
}

// Regression test for #5883: the evidence of a control is read from the
// resource's object, so in a report made with --encrypt a container image is
// ciphertext there, and decrypt used to reject the whole report.
func TestEncryptedReportWithImageEvidenceCanBeDecrypted(t *testing.T) {
	const masterKey = "01234567890123456789012345678901"
	t.Setenv("KUBESCAPE_MASTER_KEY", masterKey)
	t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

	dir := t.TempDir()
	writeFile := func(name, contents string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
		return path
	}
	writeFile("input/pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx:1.25\n")

	// A control whose failing path is the container image, like C-0078 and C-0236.
	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}},
		Rule: `package armo_builtins
import rego.v1

deny contains msg if {
	pod := input[_]
	msg := {"alertObject": {"k8sApiObjects": [pod]}, "reviewPaths": ["spec.containers[0].image"]}
}
`,
	}
	rule.Name = "image-evidence"
	control := reporthandling.Control{ControlID: "C-0078", BaseScore: 7, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Image evidence"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "image-evidence"
	policyJSON, err := json.Marshal(framework)
	require.NoError(t, err)

	info := &cautils.ScanInfo{
		InputPatterns:     []string{filepath.Join(dir, "input")},
		UseFrom:           []string{writeFile("image-evidence.json", string(policyJSON))},
		ControlsInputs:    writeFile("controls-inputs.json", `{"probe":["value"]}`),
		UseExceptions:     writeFile("exceptions.json", "[]"),
		AttackTracks:      writeFile("attack-tracks.json", "[]"),
		ScanType:          cautils.ScanTypeFramework,
		FrameworkScan:     true,
		NoClusterAccess:   true,
		Local:             true,
		EncryptionEnabled: true,
	}
	info.Submit.SetBool(false)
	policies := cautils.BuildPolicyIdentifiers([]string{framework.Name}, apisv1.KindFramework)

	results, err := NewKubescape(t.Context()).ScanContext(context.Background(), info, policies)
	require.NoError(t, err)
	encrypted, err := results.ToJson()
	require.NoError(t, err)

	// The image is evidence of the control, and encrypted there.
	var before reportEvidence
	require.NoError(t, json.Unmarshal(encrypted, &before))
	require.Len(t, before.Results, 1)
	require.Len(t, before.Results[0].Controls, 1)
	require.Len(t, before.Results[0].Controls[0].Evidence, 1)
	assert.Equal(t, "spec.containers[0].image", before.Results[0].Controls[0].Evidence[0].Path)
	require.Contains(t, before.Results[0].Controls[0].Evidence[0].Value, "ENC[AES256_GCM,")
	assert.NotContains(t, string(encrypted), "nginx:1.25")

	decrypted, err := reportcrypto.DecryptReport(encrypted, []byte(masterKey))
	require.NoError(t, err, "a report with image evidence must be decryptable")

	var after reportEvidence
	require.NoError(t, json.Unmarshal(decrypted, &after))
	require.Len(t, after.Results, 1)
	require.Len(t, after.Results[0].Controls, 1)
	require.Len(t, after.Results[0].Controls[0].Evidence, 1)
	assert.Equal(t, "spec.containers[0].image", after.Results[0].Controls[0].Evidence[0].Path)
	assert.Equal(t, "nginx:1.25", after.Results[0].Controls[0].Evidence[0].Value)
}
