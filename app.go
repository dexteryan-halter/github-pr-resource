package resource

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultV3Endpoint = "https://api.github.com"

// usesGithubApp reports whether the source authenticates as a GitHub App
// instead of with a static access token.
func (s *Source) usesGithubApp() bool {
	return s.AppID != 0 || s.AppPrivateKey != "" || s.AppInstallationID != 0
}

// ResolveAccessToken makes sure s.AccessToken holds a usable token. With a
// static access_token it does nothing. With GitHub App credentials it mints a
// short-lived installation token, scoped to the configured repository.
//
// The App credentials in the source never change, so the source (and with it
// the identity Concourse gives this resource) stays stable while the token
// used for API calls and git is always fresh.
func (s *Source) ResolveAccessToken() error {
	if !s.usesGithubApp() {
		return nil
	}
	owner, repository, err := parseRepository(s.Repository)
	if err != nil {
		return err
	}
	key, err := parsePrivateKey(s.AppPrivateKey)
	if err != nil {
		return err
	}
	jwt, err := appJWT(s.AppID, key, time.Now())
	if err != nil {
		return err
	}

	app := &appClient{
		baseURL: v3BaseURL(s.V3Endpoint),
		jwt:     jwt,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	if s.SkipSSLVerification {
		app.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	installationID := s.AppInstallationID
	if installationID == 0 {
		installationID, err = app.findInstallation(owner, repository)
		if err != nil {
			return err
		}
	}
	token, err := app.createInstallationToken(installationID, repository)
	if err != nil {
		return err
	}
	s.AccessToken = token
	return nil
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, errors.New("app_private_key is not a PEM encoded key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse app_private_key: %s", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("app_private_key must be an RSA key")
	}
	return key, nil
}

// appJWT builds the RS256 JSON Web Token GitHub expects from an App.
// Issued-at is backdated a minute to allow for clock drift, and the token
// expires well inside GitHub's ten minute limit.
func appJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]interface{}{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(appID, 10),
	})
	if err != nil {
		return "", err
	}
	signingInput := header + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign app token: %s", err)
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

// v3BaseURL matches how go-github treats an enterprise endpoint: the REST API
// lives under /api/v3 unless the endpoint already says so.
func v3BaseURL(endpoint string) string {
	if endpoint == "" {
		return defaultV3Endpoint
	}
	base := strings.TrimSuffix(endpoint, "/")
	if base == defaultV3Endpoint || strings.HasSuffix(base, "/api/v3") {
		return base
	}
	return base + "/api/v3"
}

type appClient struct {
	baseURL string
	jwt     string
	http    *http.Client
}

func (a *appClient) do(method, path string, body interface{}, wantStatus int, out interface{}) error {
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, a.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+a.jwt)
	req.Header.Set("User-Agent", "github-pr-resource")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %s", method, path, err)
	}
	defer resp.Body.Close()
	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("%s %s: unexpected status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return json.Unmarshal(payload, out)
}

func (a *appClient) findInstallation(owner, repository string) (int64, error) {
	var result struct {
		ID int64 `json:"id"`
	}
	path := fmt.Sprintf("/repos/%s/%s/installation", owner, repository)
	if err := a.do(http.MethodGet, path, nil, http.StatusOK, &result); err != nil {
		return 0, fmt.Errorf("failed to find app installation for %s/%s: %s", owner, repository, err)
	}
	if result.ID == 0 {
		return 0, fmt.Errorf("no app installation found for %s/%s", owner, repository)
	}
	return result.ID, nil
}

func (a *appClient) createInstallationToken(installationID int64, repository string) (string, error) {
	var result struct {
		Token string `json:"token"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	body := map[string]interface{}{"repositories": []string{repository}}
	if err := a.do(http.MethodPost, path, body, http.StatusCreated, &result); err != nil {
		return "", fmt.Errorf("failed to create app installation token: %s", err)
	}
	if result.Token == "" {
		return "", errors.New("github returned an empty installation token")
	}
	return result.Token, nil
}
