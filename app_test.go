package resource_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	resource "github.com/telia-oss/github-pr-resource"
)

func testKey(t *testing.T, pkcs8 bool) (*rsa.PrivateKey, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	return key, string(pem.EncodeToMemory(block))
}

// verifyJWT checks the bearer token is an RS256 token signed by key and
// issued by appID.
func verifyJWT(t *testing.T, r *http.Request, key *rsa.PrivateKey, appID string) {
	auth := r.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "Bearer "), "missing bearer token")
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	require.Len(t, parts, 3)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(rawClaims, &claims))
	assert.Equal(t, appID, claims.Iss)
	assert.True(t, claims.Exp-claims.Iat <= 600, "token lifetime must not exceed ten minutes")
}

type fakeGithubApp struct {
	t              *testing.T
	key            *rsa.PrivateKey
	lookups        int
	tokenRequested string
	tokenRepos     []string
}

func (f *fakeGithubApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verifyJWT(f.t, r, f.key, "42")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/repos/itsdalmo/test-repository/installation":
		f.lookups++
		w.Write([]byte(`{"id": 1001}`))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v3/app/installations/"):
		f.tokenRequested = r.URL.Path
		var body struct {
			Repositories []string `json:"repositories"`
		}
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
		f.tokenRepos = body.Repositories
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"token": "ghs_minted"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}
}

func TestResolveAccessToken(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		key, pemKey := testKey(t, pkcs8)

		t.Run("looks up the installation when not given", func(t *testing.T) {
			fake := &fakeGithubApp{t: t, key: key}
			server := httptest.NewServer(fake)
			defer server.Close()

			s := resource.Source{
				Repository:    "itsdalmo/test-repository",
				AppID:         42,
				AppPrivateKey: pemKey,
				V3Endpoint:    server.URL,
				V4Endpoint:    server.URL + "/api/graphql",
			}
			require.NoError(t, s.Validate())
			require.NoError(t, s.ResolveAccessToken())

			assert.Equal(t, "ghs_minted", s.AccessToken)
			assert.Equal(t, 1, fake.lookups)
			assert.Equal(t, "/api/v3/app/installations/1001/access_tokens", fake.tokenRequested)
			assert.Equal(t, []string{"test-repository"}, fake.tokenRepos)
		})

		t.Run("uses the given installation", func(t *testing.T) {
			fake := &fakeGithubApp{t: t, key: key}
			server := httptest.NewServer(fake)
			defer server.Close()

			s := resource.Source{
				Repository:        "itsdalmo/test-repository",
				AppID:             42,
				AppInstallationID: 7,
				AppPrivateKey:     pemKey,
				V3Endpoint:        server.URL + "/api/v3/",
				V4Endpoint:        server.URL + "/api/graphql",
			}
			require.NoError(t, s.ResolveAccessToken())

			assert.Equal(t, "ghs_minted", s.AccessToken)
			assert.Equal(t, 0, fake.lookups)
			assert.Equal(t, "/api/v3/app/installations/7/access_tokens", fake.tokenRequested)
		})
	}

	t.Run("reports a missing installation", func(t *testing.T) {
		key, pemKey := testKey(t, false)
		server := httptest.NewServer(&fakeGithubApp{t: t, key: key})
		defer server.Close()

		s := resource.Source{
			Repository:    "itsdalmo/not-installed",
			AppID:         42,
			AppPrivateKey: pemKey,
			V3Endpoint:    server.URL,
			V4Endpoint:    server.URL + "/api/graphql",
		}
		err := s.ResolveAccessToken()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find app installation")
		assert.Empty(t, s.AccessToken)
	})

	t.Run("leaves a static access token alone", func(t *testing.T) {
		s := resource.Source{Repository: "itsdalmo/test-repository", AccessToken: "static"}
		require.NoError(t, s.ResolveAccessToken())
		assert.Equal(t, "static", s.AccessToken)
	})

	t.Run("rejects a key that is not PEM", func(t *testing.T) {
		s := resource.Source{Repository: "itsdalmo/test-repository", AppID: 42, AppPrivateKey: "nope"}
		assert.Error(t, s.ResolveAccessToken())
	})
}

func TestValidateAuth(t *testing.T) {
	cases := []struct {
		name    string
		source  resource.Source
		wantErr string
	}{
		{"no credentials", resource.Source{Repository: "a/b"}, "must be set"},
		{"static token", resource.Source{Repository: "a/b", AccessToken: "x"}, ""},
		{"app credentials", resource.Source{Repository: "a/b", AppID: 1, AppPrivateKey: "k"}, ""},
		{"app without key", resource.Source{Repository: "a/b", AppID: 1}, "app_id and app_private_key"},
		{"key without app", resource.Source{Repository: "a/b", AppPrivateKey: "k"}, "app_id and app_private_key"},
		{"both kinds", resource.Source{Repository: "a/b", AccessToken: "x", AppID: 1, AppPrivateKey: "k"}, "not both"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.source.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
