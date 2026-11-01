// SPDX-License-Identifier: Apache-2.0
package hvreceipts_test

import (
	"encoding/base64"
	"fmt"
	"encoding/json"
	"os"
	"testing"

	"github.com/hypereum-innovations/receipts-sdk-go/hvreceipts"
)

func readVectorsJSON(t *testing.T) []byte {
	t.Helper()
	if data, err := os.ReadFile("testdata/vectors.json"); err == nil {
		return data
	}
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Shared conformance vectors (same file as TS/Rust/Python). Cases that need a
// consistency chain or batch proof are exercised by those verifiers today;
// the Go core asserts every same-checkpoint case plus the failure classes.
func TestSharedVectors(t *testing.T) {
	data := readVectorsJSON(t)
	var suite struct {
		Trust json.RawMessage `json:"trust"`
		Cases []struct {
			Name        string          `json:"name"`
			Expect      string          `json:"expect"`
			Statement   string          `json:"statement"`
			Checkpoint  string          `json:"checkpoint"`
			Disclosure  map[string]any  `json:"disclosure"`
			RevokedKids []string        `json:"revoked_kids"`
			DropIssuers []string        `json:"drop_issuers"`
			Batch       json.RawMessage `json:"batch"`
			Consistency json.RawMessage `json:"consistency_chain"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	for _, c := range suite.Cases {
		if len(c.Batch) > 0 || len(c.Consistency) > 0 {
			t.Logf("skip %s (batch/consistency in TS+Rust+Python)", c.Name)
			continue
		}
		trust, err := hvreceipts.LoadTrustFile(suite.Trust)
		if err != nil {
			t.Fatal(err)
		}
		for _, kid := range c.RevokedKids {
			entry := trust.Issuers[kid]
			entry.Revoked = true
			trust.Issuers[kid] = entry
		}
		for _, kid := range c.DropIssuers {
			delete(trust.Issuers, kid)
		}
		stmt, err := base64.StdEncoding.DecodeString(c.Statement)
		if err != nil {
			t.Fatal(err)
		}
		report := hvreceipts.VerifyReceipt(stmt, trust, c.Checkpoint, c.Disclosure)
		if report.Verdict != c.Expect {
			t.Errorf("%s: got %s want %s (%+v)", c.Name, report.Verdict, c.Expect, report.Checks)
		}
		if len(c.RevokedKids) == 0 && len(c.DropIssuers) == 0 {
			if rustRep, err := hvreceipts.VerifyViaRustCore(stmt, suite.Trust, c.Checkpoint, c.Disclosure); err == nil {
				if rustRep.Verdict != c.Expect {
					t.Errorf("%s (Rust core): got %s want %s", c.Name, rustRep.Verdict, c.Expect)
				}
			}
		}
	}
}

func TestConsistencyAndBatchVectors(t *testing.T) {
	data := readVectorsJSON(t)
	var suite struct {
		Trust json.RawMessage `json:"trust"`
		Cases []struct {
			Name      string `json:"name"`
			Expect    string `json:"expect"`
			Statement string `json:"statement"`
			Chain     *struct {
				RootAtReceipt string `json:"root_at_receipt"`
				Proof         struct {
					FirstSize  uint64   `json:"first_size"`
					SecondSize uint64   `json:"second_size"`
					Hashes     []string `json:"hashes"`
				} `json:"proof"`
			} `json:"consistency_chain"`
			Checkpoint string `json:"checkpoint"`
			Batch      *struct {
				Capsule string `json:"capsule"`
				Proof   struct {
					TreeSize  uint64   `json:"treeSize"`
					LeafIndex uint64   `json:"leafIndex"`
					Hashes    []string `json:"hashes"`
				} `json:"proof"`
			} `json:"batch"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	trust, err := hvreceipts.LoadTrustFile(suite.Trust)
	if err != nil {
		t.Fatal(err)
	}
	toHashes := func(xs []string) [][32]byte {
		out := make([][32]byte, len(xs))
		for i, x := range xs {
			b, _ := base64.StdEncoding.DecodeString(x)
			copy(out[i][:], b)
		}
		return out
	}
	for _, c := range suite.Cases {
		stmt, _ := base64.StdEncoding.DecodeString(c.Statement)
		if c.Chain != nil {
			rootBytes, _ := base64.StdEncoding.DecodeString(c.Chain.RootAtReceipt)
			var root [32]byte
			copy(root[:], rootBytes)
			got := hvreceipts.VerifyWithConsistency(stmt, trust, c.Checkpoint, root,
				c.Chain.Proof.FirstSize, c.Chain.Proof.SecondSize, toHashes(c.Chain.Proof.Hashes))
			if got != (c.Expect == "VERIFIED") {
				t.Errorf("%s: consistency got %v want %s", c.Name, got, c.Expect)
			}
		}
		if c.Batch != nil {
			capsule, _ := base64.StdEncoding.DecodeString(c.Batch.Capsule)
			v, err := hvreceipts.Unmarshal(mustPayload(t, stmt))
			if err != nil {
				t.Fatal(err)
			}
			m := v.(map[any]any)
			rootHex := m["batch_root"].(string)[len("sha256:"):]
			var root [32]byte
			for i := 0; i < 32; i++ {
				var b byte
				_, _ = fmt.Sscanf(rootHex[2*i:2*i+2], "%02x", &b)
				root[i] = b
			}
			got := hvreceipts.VerifyBatchInclusion(capsule, c.Batch.Proof.TreeSize, c.Batch.Proof.LeafIndex,
				toHashes(c.Batch.Proof.Hashes), root)
			if got != (c.Expect == "VERIFIED") {
				t.Errorf("%s: batch got %v want %s", c.Name, got, c.Expect)
			}
		}
	}
}

func mustPayload(t *testing.T, stmt []byte) []byte {
	t.Helper()
	v, err := hvreceipts.Unmarshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if tag, ok := v.(hvreceipts.Tag); ok {
		v = tag.Value
	}
	arr := v.([]any)
	payload, _ := arr[2].([]byte)
	return payload
}
