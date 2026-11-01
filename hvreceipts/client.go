// SPDX-License-Identifier: Apache-2.0
package hvreceipts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Signer signs COSE Sig_structures locally (ES256 or Ed25519). Production
// custody swaps this for a KMS-backed implementation of the same interface.
type Signer interface {
	Alg() int64
	Kid() string
	Sign(msg []byte) ([]byte, error)
	COSEKey() []byte
}

// ES256Signer wraps an ecdsa P-256 key.
type ES256Signer struct {
	Key *ecdsa.PrivateKey
	ID  string
}

func (s *ES256Signer) Alg() int64  { return -7 }
func (s *ES256Signer) Kid() string { return s.ID }
func (s *ES256Signer) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	ss.FillBytes(out[32:])
	return out, nil
}
func (s *ES256Signer) COSEKey() []byte {
	out, _ := Marshal(map[any]any{
		int64(1): int64(2), int64(2): []byte(s.ID), int64(3): int64(-7), int64(-1): int64(1),
		int64(-2): pad32(s.Key.PublicKey.X), int64(-3): pad32(s.Key.PublicKey.Y),
	})
	return out
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

// Ed25519Signer wraps an ed25519 key.
type Ed25519Signer struct {
	Key ed25519.PrivateKey
	ID  string
}

func (s *Ed25519Signer) Alg() int64              { return -8 }
func (s *Ed25519Signer) Kid() string             { return s.ID }
func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.Key, msg), nil
}
func (s *Ed25519Signer) COSEKey() []byte {
	out, _ := Marshal(map[any]any{
		int64(1): int64(1), int64(2): []byte(s.ID), int64(3): int64(-8), int64(-1): int64(6),
		int64(-2): []byte(s.Key.Public().(ed25519.PublicKey)),
	})
	return out
}

// SignStatement builds a tagged COSE_Sign1 over payload.
func SignStatement(signer Signer, payload []byte, contentType, iss, sub string, iat int64) ([]byte, error) {
	prot := map[any]any{int64(1): signer.Alg(), int64(3): contentType, int64(4): []byte(signer.Kid())}
	if iss != "" {
		prot[int64(15)] = map[any]any{int64(1): iss, int64(2): sub, int64(6): iat}
	}
	protBytes, err := Marshal(prot)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(sigStructure(protBytes, nil, payload))
	if err != nil {
		return nil, err
	}
	return Marshal(Tag{18, []any{protBytes, map[any]any{}, payload, sig}})
}

// Client talks to a Hivemind Receipts service.
type Client struct {
	BaseURL string
	Signer  Signer
	HTTP    *http.Client
}

func (c *Client) post(path string, body []byte, contentType string) (int, http.Header, []byte, error) {
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	res, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, data, err
}

// RegisterSelfServe registers the client key as a T0 issuer.
func (c *Client) RegisterSelfServe() error {
	body, _ := json.Marshal(map[string]string{
		"cose_key": base64.RawURLEncoding.EncodeToString(c.Signer.COSEKey()),
	})
	status, _, data, err := c.post("/issuers/selfserve", body, "application/json")
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("self-serve registration: %s", data)
	}
	return nil
}

// Register submits a signed statement; returns the transparent statement.
func (c *Client) Register(statement []byte) ([]byte, error) {
	status, _, data, err := c.post("/transparency/entries", statement, "application/cose")
	if err != nil {
		return nil, err
	}
	if status != 201 {
		return nil, fmt.Errorf("registration refused (%d): %s", status, data)
	}
	return data, nil
}

// Checkpoint fetches the current cosigned checkpoint text.
func (c *Client) Checkpoint() (string, error) {
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Get(c.BaseURL + "/transparency/checkpoint")
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	return string(data), err
}

// NowIat is a convenience for CWT issued-at.
func NowIat() int64 { return time.Now().Unix() }
