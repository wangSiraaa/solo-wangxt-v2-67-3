package registry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

// TestHTTPExemptionRoundTrip drives the exemption workflow over real HTTP:
// request, self-approval rejection, approval, and the release decision in
// the check response.
func TestHTTPExemptionRoundTrip(t *testing.T) {
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

	v1 := `syntax = "proto3"; package acme.http; message M { int32 a = 1; }`
	v2 := `syntax = "proto3"; package acme.http; message M { string a = 1; }`
	for _, reg := range []map[string]any{
		{"package": "acme.http", "version": "v1", "files": []map[string]string{{"path": "a.proto", "content": v1}}},
		{"package": "acme.http", "version": "v2", "files": []map[string]string{{"path": "a.proto", "content": v2}}},
	} {
		if code, out := post(ProcedureRegisterVersion, reg); code != http.StatusOK {
			t.Fatalf("register: status %d, body %v", code, out)
		}
	}

	// The check response carries the release decision next to the raw report.
	code, out := post(ProcedureCheckCompatibility, map[string]any{
		"package": "acme.http", "base_version": "v1", "candidate_version": "v2",
	})
	if code != http.StatusOK {
		t.Fatalf("check: status %d, body %v", code, out)
	}
	release, ok := out["release"].(map[string]any)
	if !ok || release["raw_verdict"] != "INCOMPATIBLE" || release["effective_verdict"] != "INCOMPATIBLE" {
		t.Fatalf("release = %v", out["release"])
	}
	findings := release["findings"].([]any)
	fp := findings[0].(map[string]any)["fingerprint"].(string)

	// File the exemption.
	code, out = post(ProcedureRequestExemption, map[string]any{
		"package": "acme.http", "base_version": "v1", "head_version": "v2",
		"fingerprint": fp, "owner": "team-pay", "reason": "migration window",
		"consumers": []string{"*"}, "expires_at": "2027-01-01T00:00:00Z", "requested_by": "alice",
	})
	if code != http.StatusOK {
		t.Fatalf("request: status %d, body %v", code, out)
	}
	exemption := out["exemption"].(map[string]any)
	if exemption["status"] != "PENDING" {
		t.Fatalf("status = %v, want PENDING", exemption["status"])
	}
	id := exemption["id"].(string)
	version := int64(exemption["version"].(float64))

	// Self-approval is rejected.
	code, out = post(ProcedureApproveExemption, map[string]any{
		"id": id, "expected_version": version, "approver": "alice",
	})
	if code == http.StatusOK || out["code"] != "permission_denied" {
		t.Fatalf("self-approval: status %d, body %v", code, out)
	}

	// A second identity approves.
	code, out = post(ProcedureApproveExemption, map[string]any{
		"id": id, "expected_version": version, "approver": "bob",
	})
	if code != http.StatusOK || out["exemption"].(map[string]any)["status"] != "APPROVED" {
		t.Fatalf("approve: status %d, body %v", code, out)
	}

	// The wildcard exemption lifts the effective verdict; the raw report
	// still says INCOMPATIBLE.
	code, out = post(ProcedureCheckCompatibility, map[string]any{
		"package": "acme.http", "base_version": "v1", "candidate_version": "v2",
	})
	if code != http.StatusOK {
		t.Fatalf("check after approval: status %d", code)
	}
	release = out["release"].(map[string]any)
	if release["raw_verdict"] != "INCOMPATIBLE" || release["effective_verdict"] != "COMPATIBLE" {
		t.Fatalf("release after approval = %v", release)
	}
	if out["report"].(map[string]any)["verdict"] != "INCOMPATIBLE" {
		t.Fatalf("report rewritten: %v", out["report"])
	}
}
