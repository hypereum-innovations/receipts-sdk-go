// SPDX-License-Identifier: Apache-2.0
package hvreceipts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func sha(b []byte) [32]byte { return sha256.Sum256(b) }

func leafHash(data []byte) [32]byte { return sha256.Sum256(append([]byte{0}, data...)) }

func nodeHash(l, r [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func verifyInclusion(leaf [32]byte, size, index uint64, hashes [][32]byte, root [32]byte) bool {
	if index >= size || size < 1 {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range hashes {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

type sign1 struct {
	protBytes []byte
	prot      map[any]any
	unprot    map[any]any
	payload   []byte
	hasBody   bool
	signature []byte
}

func (s *sign1) alg() int64 {
	if v, ok := s.prot[int64(1)].(int64); ok {
		return v
	}
	return 0
}

func (s *sign1) kid() string {
	if v, ok := s.prot[int64(4)].([]byte); ok {
		return string(v)
	}
	return ""
}

func parseSign1(data []byte) (*sign1, error) {
	v, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	if t, ok := v.(Tag); ok {
		if t.Tag != 18 {
			return nil, fmt.Errorf("expected COSE_Sign1 tag")
		}
		v = t.Value
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 {
		return nil, fmt.Errorf("COSE_Sign1 must be array of 4")
	}
	protBytes, _ := arr[0].([]byte)
	prot := map[any]any{}
	if len(protBytes) > 0 {
		pv, err := Unmarshal(protBytes)
		if err != nil {
			return nil, err
		}
		prot, _ = pv.(map[any]any)
	}
	unprot, _ := arr[1].(map[any]any)
	payload, hasBody := arr[2].([]byte)
	sig, _ := arr[3].([]byte)
	return &sign1{protBytes: protBytes, prot: prot, unprot: unprot, payload: payload, hasBody: hasBody, signature: sig}, nil
}

func sigStructure(prot, aad, payload []byte) []byte {
	out, _ := Marshal([]any{"Signature1", prot, aad, payload})
	return out
}

// PublicKey is an ES256 (x,y) or Ed25519 (raw,32) public key.
type PublicKey struct {
	Alg int64
	X   []byte
	Y   []byte
	Raw []byte
}

// ParseCOSEKey decodes a COSE_Key into (kid, key).
func ParseCOSEKey(data []byte) (string, PublicKey, error) {
	v, err := Unmarshal(data)
	if err != nil {
		return "", PublicKey{}, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return "", PublicKey{}, fmt.Errorf("cose key not a map")
	}
	kid := ""
	if b, ok := m[int64(2)].([]byte); ok {
		kid = string(b)
	}
	switch m[int64(1)] {
	case int64(2):
		x, _ := m[int64(-2)].([]byte)
		y, _ := m[int64(-3)].([]byte)
		return kid, PublicKey{Alg: -7, X: x, Y: y}, nil
	case int64(1):
		x, _ := m[int64(-2)].([]byte)
		return kid, PublicKey{Alg: -8, Raw: x}, nil
	}
	return "", PublicKey{}, fmt.Errorf("unsupported COSE key type")
}

func verifySig(key PublicKey, msg, sig []byte) bool {
	switch key.Alg {
	case -7:
		if len(sig) != 64 {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(key.X), Y: new(big.Int).SetBytes(key.Y)}
		digest := sha(msg)
		return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case -8:
		return ed25519.Verify(ed25519.PublicKey(key.Raw), msg, sig)
	}
	return false
}

// IssuerTrust is one issuer entry in the trust roots.
type IssuerTrust struct {
	Key     PublicKey
	Tier    string
	Display string
	Revoked bool
}

// TrustRoots pins everything a relying party trusts. Load it from the TUF
// repository in production; from a file in tests.
type TrustRoots struct {
	Issuers       map[string]IssuerTrust
	LogKeys       map[string]PublicKey
	NoteVerifiers []noteVerifier
	Quorum        int
	WitnessNames  map[string]bool
}

type noteVerifier struct {
	name    string
	keyID   []byte
	keyType byte
	raw     []byte
}

func parseNoteVerifier(s string) (noteVerifier, error) {
	first := strings.Index(s, "+")
	if first < 0 {
		return noteVerifier{}, fmt.Errorf("bad verifier string")
	}
	second := strings.Index(s[first+1:], "+")
	if second < 0 {
		return noteVerifier{}, fmt.Errorf("bad verifier string")
	}
	second += first + 1
	keyBytes, err := base64.StdEncoding.DecodeString(s[second+1:])
	if err != nil {
		return noteVerifier{}, err
	}
	id, err := hex.DecodeString(s[first+1 : second])
	if err != nil || len(keyBytes) < 1 {
		return noteVerifier{}, fmt.Errorf("bad verifier string")
	}
	return noteVerifier{name: s[:first], keyID: id, keyType: keyBytes[0], raw: keyBytes[1:]}, nil
}

// LoadTrustFile parses the roots.json format shared by all verifiers.
func LoadTrustFile(data []byte) (*TrustRoots, error) {
	var f struct {
		Issuers []struct {
			Kid     string `json:"kid"`
			CoseKey string `json:"cose_key"`
			Tier    string `json:"tier"`
			Display string `json:"display"`
		} `json:"issuers"`
		LogKeys []struct {
			Kid     string `json:"kid"`
			CoseKey string `json:"cose_key"`
		} `json:"log_keys"`
		NoteVerifiers []string `json:"note_verifiers"`
		WitnessPolicy struct {
			Quorum    int `json:"quorum"`
			Witnesses []struct {
				Name string `json:"name"`
			} `json:"witnesses"`
		} `json:"witness_policy"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	t := &TrustRoots{Issuers: map[string]IssuerTrust{}, LogKeys: map[string]PublicKey{}, WitnessNames: map[string]bool{}}
	for _, i := range f.Issuers {
		raw, err := base64.RawURLEncoding.DecodeString(i.CoseKey)
		if err != nil {
			return nil, err
		}
		_, key, err := ParseCOSEKey(raw)
		if err != nil {
			return nil, err
		}
		t.Issuers[i.Kid] = IssuerTrust{Key: key, Tier: i.Tier, Display: i.Display}
	}
	for _, l := range f.LogKeys {
		raw, err := base64.RawURLEncoding.DecodeString(l.CoseKey)
		if err != nil {
			return nil, err
		}
		_, key, err := ParseCOSEKey(raw)
		if err != nil {
			return nil, err
		}
		t.LogKeys[l.Kid] = key
	}
	for _, nv := range f.NoteVerifiers {
		if parsed, err := parseNoteVerifier(nv); err == nil {
			t.NoteVerifiers = append(t.NoteVerifiers, parsed)
		}
	}
	t.Quorum = f.WitnessPolicy.Quorum
	for _, w := range f.WitnessPolicy.Witnesses {
		t.WitnessNames[w.Name] = true
	}
	return t, nil
}

// Check is one line of the structured verification report.
type Check struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Report is the outcome of Class-1 offline verification.
type Report struct {
	Verdict   string  `json:"verdict"`
	Checks    []Check `json:"checks"`
	CapsuleID string  `json:"capsule_id,omitempty"`
}

func digestOf(b []byte) string {
	sum := sha(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func capsuleIDOf(payload []byte) (string, map[any]any, error) {
	v, err := Unmarshal(payload)
	if err != nil {
		return "", nil, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return "", nil, fmt.Errorf("capsule not a map")
	}
	id, _ := m["capsule_id"].(string)
	core := map[any]any{}
	for k, val := range m {
		if k != "capsule_id" {
			core[k] = val
		}
	}
	enc, err := Marshal(core)
	if err != nil {
		return "", nil, err
	}
	if digestOf(enc) != id {
		return "", nil, fmt.Errorf("capsule_id mismatch")
	}
	if m["profile"] != "urn:hivemind:receipts:capsule:1" {
		return "", nil, fmt.Errorf("bad capsule profile")
	}
	return id, m, nil
}

func parseCheckpoint(text string) (origin string, size uint64, root [32]byte, body string, sigs []struct {
	name  string
	keyID []byte
	sig   []byte
}, err error) {
	parts := strings.SplitN(text, "\n\n", 2)
	if len(parts) != 2 {
		return "", 0, root, "", nil, fmt.Errorf("no signature block")
	}
	body = parts[0] + "\n"
	lines := strings.Split(parts[0], "\n")
	if len(lines) < 3 {
		return "", 0, root, "", nil, fmt.Errorf("checkpoint too short")
	}
	origin = lines[0]
	size, err = strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return "", 0, root, "", nil, err
	}
	rawRoot, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(rawRoot) != 32 {
		return "", 0, root, "", nil, fmt.Errorf("bad root")
	}
	copy(root[:], rawRoot)
	for _, line := range strings.Split(parts[1], "\n") {
		if line == "" {
			continue
		}
		rest := strings.TrimPrefix(line, "— ")
		sp := strings.Index(rest, " ")
		raw, err := base64.StdEncoding.DecodeString(rest[sp+1:])
		if err != nil || len(raw) < 5 {
			return "", 0, root, "", nil, fmt.Errorf("bad sig line")
		}
		sigs = append(sigs, struct {
			name  string
			keyID []byte
			sig   []byte
		}{rest[:sp], raw[:4], raw[4:]})
	}
	return origin, size, root, body, sigs, nil
}


// parseInclusion reads an RFC 9942 vdp value: {-1: [bstr .cbor [size, index,
// [path]]]} from the unprotected header (legacy inline form also accepted).
func parseInclusion(rp *sign1) (uint64, uint64, [][32]byte, bool) {
	vdpRaw, ok := rp.unprot[int64(396)]
	if !ok {
		vdpRaw = rp.prot[int64(396)]
	}
	vdp, _ := vdpRaw.(map[any]any)
	inc, _ := vdp[int64(-1)].([]any)
	if len(inc) == 0 {
		return 0, 0, nil, false
	}
	var ts, idx int64
	var rawHashes []any
	if wrapped, ok := inc[0].([]byte); ok {
		cv, err := Unmarshal(wrapped)
		if err != nil {
			return 0, 0, nil, false
		}
		content, _ := cv.([]any)
		if len(content) != 3 {
			return 0, 0, nil, false
		}
		ts, _ = content[0].(int64)
		idx, _ = content[1].(int64)
		rawHashes, _ = content[2].([]any)
	} else {
		if len(inc) < 2 {
			return 0, 0, nil, false
		}
		ts, _ = inc[0].(int64)
		idx, _ = inc[1].(int64)
		rawHashes = inc[2:]
	}
	hashes := make([][32]byte, 0, len(rawHashes))
	for _, h := range rawHashes {
		b, ok := h.([]byte)
		if !ok || len(b) != 32 {
			return 0, 0, nil, false
		}
		var a [32]byte
		copy(a[:], b)
		hashes = append(hashes, a)
	}
	return uint64(ts), uint64(idx), hashes, true
}

// VerifyReceipt runs the Class-1 checks. disclosure may be nil.
func VerifyReceipt(statement []byte, trust *TrustRoots, checkpointText string, disclosure map[string]any) Report {
	var checks []Check
	push := func(name string, ok bool, detail string) {
		status := "fail"
		if ok {
			status = "pass"
		}
		checks = append(checks, Check{name, status, detail})
	}
	parsed, err := parseSign1(statement)
	if err != nil {
		return Report{Verdict: "FAILED", Checks: []Check{{"envelope", "fail", err.Error()}}}
	}
	capsuleID := ""
	issuer, known := trust.Issuers[parsed.kid()]
	if !known {
		push("issuer_identity", false, "unknown issuer kid "+parsed.kid())
	} else {
		push("issuer_identity", !issuer.Revoked, issuer.Tier+" — "+issuer.Display)
		push("signature", issuer.Key.Alg == parsed.alg() && verifySig(issuer.Key, sigStructure(parsed.protBytes, nil, parsed.payload), parsed.signature), "COSE signature")
	}
	var capsule map[any]any
	if parsed.hasBody {
		if id, m, err := capsuleIDOf(parsed.payload); err == nil {
			capsuleID, capsule = id, m
			push("capsule", true, id)
		} else {
			isBatch := false
			if v, e := Unmarshal(parsed.payload); e == nil {
				if mm, ok := v.(map[any]any); ok && mm["profile"] == "urn:hivemind:receipts:capsule-batch:1" {
					isBatch = true
				}
			}
			if isBatch {
				push("capsule", true, "capsule batch payload")
			} else {
				push("capsule", false, err.Error())
			}
		}
	} else {
		push("capsule", false, "missing payload")
	}
	if disclosure != nil && capsule != nil {
		push("disclosure", verifyDisclosure(capsule, disclosure), "salted commitments")
	}

	receipts := []any{}
	if r, ok := parsed.unprot[int64(394)].([]any); ok {
		receipts = r
	}
	if len(receipts) == 0 {
		push("inclusion", false, "no COSE receipt attached")
	} else if checkpointText == "" {
		push("inclusion", false, "no checkpoint supplied")
	} else if origin, size, root, body, sigs, err := parseCheckpoint(checkpointText); err == nil {
		unprot := map[any]any{}
		for k, v := range parsed.unprot {
			if k != int64(394) && k != int64(-25900) {
				unprot[k] = v
			}
		}
		leafBytes, _ := Marshal(Tag{18, []any{parsed.protBytes, unprot, bodyOrNil(parsed), parsed.signature}})
		leaf := leafHash(leafBytes)
		verified := false
		for _, rb := range receipts {
			raw, ok := rb.([]byte)
			if !ok {
				continue
			}
			rp, err := parseSign1(raw)
			if err != nil || rp.prot[int64(395)] != int64(1) {
				continue
			}
			ts, idx, hashes, okInc := parseInclusion(rp)
			if !okInc || ts != size {
				continue
			}
			logKey, ok := trust.LogKeys[rp.kid()]
			if !ok || !verifySig(logKey, sigStructure(rp.protBytes, nil, root[:]), rp.signature) {
				continue
			}
			if verifyInclusion(leaf, ts, idx, hashes, root) {
				verified = true
			}
		}
		push("inclusion", verified, fmt.Sprintf("leaf in %s@%d", origin, size))
		logOK := false
		validWitnesses := map[string]bool{}
		for _, s := range sigs {
			for _, v := range trust.NoteVerifiers {
				if v.name != s.name || !bytes.Equal(v.keyID, s.keyID) {
					continue
				}
				if v.keyType == 1 {
					logOK = ed25519.Verify(ed25519.PublicKey(v.raw), []byte(body), s.sig)
				}
				if v.keyType == 4 && len(s.sig) == 72 {
					ts := uint64(s.sig[0])<<56 | uint64(s.sig[1])<<48 | uint64(s.sig[2])<<40 | uint64(s.sig[3])<<32 | uint64(s.sig[4])<<24 | uint64(s.sig[5])<<16 | uint64(s.sig[6])<<8 | uint64(s.sig[7])
					msg := fmt.Sprintf("cosignature/v1\ntime %d\n%s", ts, body)
					if ed25519.Verify(ed25519.PublicKey(v.raw), []byte(msg), s.sig[8:]) {
						validWitnesses[s.name] = true
					}
				}
			}
		}
		push("checkpoint_signature", logOK, "log signed checkpoint")
		if trust.Quorum > 0 {
			count := 0
			for n := range validWitnesses {
				if trust.WitnessNames[n] {
					count++
				}
			}
			push("witness_quorum", count >= trust.Quorum, fmt.Sprintf("%d cosignatures, quorum %d", count, trust.Quorum))
		}
		if capsule != nil {
			if a, ok := capsule["assurance"].(map[any]any); ok && a["ledger_mode"] == "anchored" {
				push("anchored_claim", verified, "anchored implies verified receipt")
			}
		}
	} else {
		push("inclusion", false, err.Error())
	}
	verdict := "VERIFIED"
	for _, c := range checks {
		if c.Status == "fail" {
			verdict = "FAILED"
		}
	}
	return Report{Verdict: verdict, Checks: checks, CapsuleID: capsuleID}
}

func bodyOrNil(s *sign1) any {
	if s.hasBody {
		return s.payload
	}
	return nil
}

func saltedCommitment(salt []byte, field string, value any) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(field))
	mac.Write([]byte{0})
	enc, _ := Marshal(jsonToCBOR(value))
	mac.Write(enc)
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func jsonToCBOR(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[any]any{}
		for k, val := range x {
			out[k] = jsonToCBOR(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonToCBOR(e)
		}
		return out
	case float64:
		return int64(x)
	default:
		return v
	}
}

func verifyDisclosure(capsule map[any]any, disclosure map[string]any) bool {
	saltStr, _ := disclosure["salt"].(string)
	salt, err := base64.RawURLEncoding.DecodeString(saltStr)
	if err != nil || disclosure["capsule_id"] != capsule["capsule_id"] {
		return false
	}
	privacy, _ := capsule["privacy"].(map[any]any)
	if privacy["salt_commitment"] != digestOf(salt) {
		return false
	}
	fields, _ := disclosure["fields"].(map[string]any)
	principal, _ := capsule["principal"].(map[any]any)
	effect, _ := capsule["effect"].(map[any]any)
	expected := map[string]any{
		"principal.subject": principal["subject_commitment"],
		"request":           capsule["request_digest"],
		"response":          effect["response_digest"],
	}
	for field, commitment := range expected {
		if val, present := fields[field]; present {
			if commitment == nil || saltedCommitment(salt, field, val) != commitment {
				return false
			}
		}
	}
	return true
}

// ---- consistency chains and batch membership (full-vector parity) ----------

func verifyConsistency(firstSize, secondSize uint64, hashes [][32]byte, firstRoot, secondRoot [32]byte) bool {
	if firstSize == secondSize {
		return len(hashes) == 0 && firstRoot == secondRoot
	}
	if firstSize < 1 || firstSize >= secondSize {
		return false
	}
	if firstSize&(firstSize-1) == 0 {
		hashes = append([][32]byte{firstRoot}, hashes...)
	}
	if len(hashes) == 0 {
		return false
	}
	fn, sn := firstSize-1, secondSize-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := hashes[0], hashes[0]
	for _, c := range hashes[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return fr == firstRoot && sr == secondRoot && sn == 0
}

// VerifyWithConsistency verifies a receipt issued against an older root by
// chaining its inclusion proof to the supplied checkpoint via RFC 9162
// consistency, mirroring the TS/Rust/Python cores.
func VerifyWithConsistency(statement []byte, trust *TrustRoots, checkpointText string, rootAtReceipt [32]byte, firstSize, secondSize uint64, proofHashes [][32]byte) bool {
	_, size, root, _, _, err := parseCheckpoint(checkpointText)
	if err != nil || size != secondSize {
		return false
	}
	if !verifyConsistency(firstSize, secondSize, proofHashes, rootAtReceipt, root) {
		return false
	}
	parsed, err := parseSign1(statement)
	if err != nil {
		return false
	}
	unprot := map[any]any{}
	for k, v := range parsed.unprot {
		if k != int64(394) && k != int64(-25900) {
			unprot[k] = v
		}
	}
	leafBytes, err := Marshal(Tag{18, []any{parsed.protBytes, unprot, bodyOrNil(parsed), parsed.signature}})
	if err != nil {
		return false
	}
	leaf := leafHash(leafBytes)
	receipts, _ := parsed.unprot[int64(394)].([]any)
	for _, rb := range receipts {
		raw, ok := rb.([]byte)
		if !ok {
			continue
		}
		rp, err := parseSign1(raw)
		if err != nil || rp.prot[int64(395)] != int64(1) {
			continue
		}
		ts, idx, hashes, okInc := parseInclusion(rp)
		if !okInc || ts != firstSize {
			continue
		}
		logKey, ok := trust.LogKeys[rp.kid()]
		if !ok || !verifySig(logKey, sigStructure(rp.protBytes, nil, rootAtReceipt[:]), rp.signature) {
			continue
		}
		valid := true
		if valid && verifyInclusion(leaf, ts, idx, hashes, rootAtReceipt) {
			return true
		}
	}
	return false
}

// VerifyBatchInclusion checks a capsule's membership in a batch statement.
func VerifyBatchInclusion(capsuleBytes []byte, treeSize, leafIndex uint64, hashes [][32]byte, batchRoot [32]byte) bool {
	if _, _, err := capsuleIDOf(capsuleBytes); err != nil {
		return false
	}
	return verifyInclusion(leafHash(capsuleBytes), treeSize, leafIndex, hashes, batchRoot)
}

func findRustVerifierBin() (string, error) {
	if envBin := os.Getenv("HIVEMIND_VERIFY_RS_BIN"); envBin != "" {
		if st, err := os.Stat(envBin); err == nil && !st.IsDir() {
			return envBin, nil
		}
	}
	candidates := []string{
		"./bin/hivemind-receipts-verify",
		"./hivemind-receipts-verify",
		"hivemind-receipts-verify",
		"hivemind-receipts-verify",
		"receipts-verify-rs/target/release/hivemind-receipts-verify",
		"receipts-verify-rs/target/debug/hivemind-receipts-verify",
	}
	var best string
	var bestTime int64
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			if t := st.ModTime().UnixNano(); t > bestTime {
				bestTime = t
				best = c
			}
		}
	}
	if best != "" {
		return best, nil
	}
	return "", fmt.Errorf("hivemind-receipts-verify binary not found")
}

// VerifyViaRustCore invokes the canonical Rust verifier (`receipts-verify-rs`)
// via CLI/JSON bridge to guarantee 100% parity across all extensions (RFC 3161,
// SD-JWT, ERS, Cedar, CEL).
func VerifyViaRustCore(statement []byte, trustJSON []byte, checkpointText string, disclosure map[string]any) (Report, error) {
	binPath, err := findRustVerifierBin()
	if err != nil {
		return Report{Verdict: "FAILED"}, err
	}
	tmpDir, err := os.MkdirTemp("", "hv_go_bridge_*")
	if err != nil {
		return Report{Verdict: "FAILED"}, err
	}
	defer os.RemoveAll(tmpDir)

	stmtPath := filepath.Join(tmpDir, "statement.scitt")
	trustPath := filepath.Join(tmpDir, "trust.json")
	if err := os.WriteFile(stmtPath, statement, 0o600); err != nil {
		return Report{Verdict: "FAILED"}, err
	}
	if err := os.WriteFile(trustPath, trustJSON, 0o600); err != nil {
		return Report{Verdict: "FAILED"}, err
	}

	args := []string{"verify", stmtPath, "--trust", trustPath, "--json"}
	if checkpointText != "" {
		cpPath := filepath.Join(tmpDir, "checkpoint.txt")
		if err := os.WriteFile(cpPath, []byte(checkpointText), 0o600); err != nil {
			return Report{Verdict: "FAILED"}, err
		}
		args = append(args, "--checkpoint", cpPath)
	}
	if disclosure != nil {
		discBytes, err := json.Marshal(disclosure)
		if err != nil {
			return Report{Verdict: "FAILED"}, err
		}
		discPath := filepath.Join(tmpDir, "disclosure.json")
		if err := os.WriteFile(discPath, discBytes, 0o600); err != nil {
			return Report{Verdict: "FAILED"}, err
		}
		args = append(args, "--disclosure", discPath)
	}

	cmd := exec.Command(binPath, args...)
	out, _ := cmd.Output()
	if len(bytes.TrimSpace(out)) == 0 {
		return Report{Verdict: "FAILED"}, fmt.Errorf("empty output from rust verifier")
	}
	var rep Report
	if err := json.Unmarshal(out, &rep); err != nil {
		return Report{Verdict: "FAILED"}, err
	}
	return rep, nil
}
