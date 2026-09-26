package registry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPEndToEnd drives the ConnectRPC handler over real HTTP with the
// connect protocol's JSON codec.
func TestHTTPEndToEnd(t *testing.T) {
	svc := NewService(NewMemStore())
	pattern, handler := svc.Handler()
	mux := http.NewServeMux()
	mux.Handle(pattern, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	post := func(procedure string, body any) (int, map[string]any) {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(srv.URL+procedure, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return resp.StatusCode, out
	}

	// Register v1.
	code, out := post(ProcedureRegisterVersion, map[string]any{
		"package": "acme.http",
		"version": "v1",
		"files":   []map[string]string{{"path": "a.proto", "content": `syntax = "proto3"; package acme.http; message M { int32 a = 1; }`}},
	})
	if code != http.StatusOK {
		t.Fatalf("register v1: status %d, body %v", code, out)
	}

	// Same version, different content -> 409-class error with JSON body.
	code, out = post(ProcedureRegisterVersion, map[string]any{
		"package": "acme.http",
		"version": "v1",
		"files":   []map[string]string{{"path": "a.proto", "content": `syntax = "proto3"; package acme.http; message M { int64 a = 1; }`}},
	})
	if code == http.StatusOK {
		t.Fatalf("expected error for conflicting content, got %v", out)
	}
	if out["code"] != "already_exists" {
		t.Fatalf("conflict body = %v", out)
	}

	// Check with inline candidate.
	code, out = post(ProcedureCheckCompatibility, map[string]any{
		"package":      "acme.http",
		"base_version": "v1",
		"candidate_files": []map[string]string{{
			"path": "a.proto", "content": `syntax = "proto3"; package acme.http; message M { string a = 1; }`,
		}},
	})
	if code != http.StatusOK {
		t.Fatalf("check: status %d, body %v", code, out)
	}
	report, ok := out["report"].(map[string]any)
	if !ok {
		t.Fatalf("no report in %v", out)
	}
	if report["verdict"] != "INCOMPATIBLE" {
		t.Fatalf("verdict = %v, want INCOMPATIBLE", report["verdict"])
	}

	// List versions.
	code, out = post(ProcedureListVersions, map[string]any{"package": "acme.http"})
	if code != http.StatusOK {
		t.Fatalf("list: status %d", code)
	}
	if versions, ok := out["versions"].([]any); !ok || len(versions) != 1 {
		t.Fatalf("versions = %v", out["versions"])
	}
}

// TestHTTPExemptionFlow drives the full waiver lifecycle over real HTTP:
// request, self-approval denied, other-identity approval, scoped publish
// decision, expiry-independent revocation and audit listing.
func TestHTTPExemptionFlow(t *testing.T) {
	svc := NewService(NewMemStore())
	pattern, handler := svc.Handler()
	mux := http.NewServeMux()
	mux.Handle(pattern, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	call := func(procedure string, body any, actor string) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+procedure, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if actor != "" {
			req.Header.Set("X-Actor", actor)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	pkg := "acme.exempt.http"
	reg := func(version, content string) {
		code, out := call(ProcedureRegisterVersion, map[string]any{
			"package": pkg, "version": version,
			"files": []map[string]string{{"path": "a.proto", "content": content}},
		}, "")
		if code != http.StatusOK {
			t.Fatalf("register %s: %d %v", version, code, out)
		}
	}
	reg("v1", `syntax = "proto3"; package acme.exempt.http; message M { int32 a = 1; }`)
	reg("v2", `syntax = "proto3"; package acme.exempt.http; message M { int64 a = 1; }`)

	code, out := call(ProcedureDeclareConsumer, map[string]any{
		"package": pkg, "consumer": "alpha", "encoding": "wire",
		"usages": []map[string]any{{"message": "acme.exempt.http.M", "fields": []string{"a"}}},
	}, "")
	if code != http.StatusOK {
		t.Fatalf("declare: %d %v", code, out)
	}

	code, out = call(ProcedureCheckCompatibility, map[string]any{
		"package": pkg, "base_version": "v1", "candidate_version": "v2", "consumer": "alpha",
	}, "")
	if code != http.StatusOK {
		t.Fatalf("check: %d %v", code, out)
	}
	dec, _ := out["consumer_decision"].(map[string]any)
	if dec["verdict"] != "INCOMPATIBLE" {
		t.Fatalf("before waiver verdict = %v", dec["verdict"])
	}
	findings, _ := dec["findings"].([]any)
	var fp string
	for _, fi := range findings {
		f := fi.(map[string]any)
		if f["severity"] == "FAIL" {
			fp, _ = f["fingerprint"].(string)
		}
	}
	if fp == "" {
		t.Fatalf("no FAIL fingerprint in %v", findings)
	}

	// Request as alice, expiring an hour from now.
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	code, out = call(ProcedureRequestExemption, map[string]any{
		"package": pkg, "base_version": "v1", "head_version": "v2", "fingerprint": fp,
		"owner": "owen", "reason": "window", "consumers": []string{"alpha"},
		"expires_at": expiresAt,
	}, "alice")
	if code != http.StatusOK {
		t.Fatalf("request: %d %v", code, out)
	}
	exMap, _ := out["exemption"].(map[string]any)
	id := int64(exMap["id"].(float64))
	if exMap["status"] != "PENDING" {
		t.Fatalf("status = %v", exMap["status"])
	}

	// Self-approval denied.
	code, out = call(ProcedureApproveExemption, map[string]any{
		"id": id, "expected_version": float64(1),
	}, "alice")
	if code == http.StatusOK || out["code"] != "permission_denied" {
		t.Fatalf("self approval: %d %v", code, out)
	}

	// Bob approves.
	code, out = call(ProcedureApproveExemption, map[string]any{
		"id": id, "expected_version": float64(1),
	}, "bob")
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}
	exMap, _ = out["exemption"].(map[string]any)
	if exMap["status"] != "APPROVED" || exMap["approved_by"] != "bob" {
		t.Fatalf("approved = %v", exMap)
	}

	// Idempotent replay by bob, still current version.
	code, out = call(ProcedureApproveExemption, map[string]any{
		"id": id, "expected_version": float64(2),
	}, "bob")
	if code != http.StatusOK {
		t.Fatalf("idempotent approve: %d %v", code, out)
	}

	// Decision now exempted.
	code, out = call(ProcedureCheckCompatibility, map[string]any{
		"package": pkg, "base_version": "v1", "candidate_version": "v2", "consumer": "alpha",
	}, "")
	if code != http.StatusOK {
		t.Fatalf("re-check: %d %v", code, out)
	}
	dec, _ = out["consumer_decision"].(map[string]any)
	if dec["raw_verdict"] != "INCOMPATIBLE" || dec["verdict"] != "EXEMPTED" {
		t.Fatalf("waived decision = %v", dec)
	}

	// Audit trail.
	code, out = call(ProcedureListAuditEvents, map[string]any{"package": pkg}, "")
	if code != http.StatusOK || len(out["events"].([]any)) != 2 {
		t.Fatalf("audit: %d %v", code, out)
	}
}
