package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// registryClient is a minimal ConnectRPC/JSON client for the exemption
// surface; it keeps the CLI free of generated code, matching the service.
type registryClient struct {
	baseURL string
	actor   string
}

func newRegistryClient(server, actor string) *registryClient {
	if server == "" {
		server = os.Getenv("REGISTRY_URL")
	}
	if server == "" {
		server = "http://localhost:8080"
	}
	if actor == "" {
		actor = os.Getenv("REGISTRY_ACTOR")
	}
	return &registryClient{baseURL: strings.TrimRight(server, "/"), actor: actor}
}

func (c *registryClient) call(procedure string, body any) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+procedure, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.actor != "" {
		req.Header.Set("X-Actor", c.actor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", procedure, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	if resp.StatusCode/100 != 2 {
		msg := string(data)
		if out != nil {
			if m, ok := out["message"].(string); ok {
				msg = m
			}
		}
		return nil, fmt.Errorf("server returned %s: %s", resp.Status, msg)
	}
	return out, nil
}

func exemptionCmd(args []string) int {
	if len(args) == 0 {
		exemptionUsage()
		return 2
	}
	action, rest := args[0], args[1:]
	var err error
	switch action {
	case "request":
		err = exemptionRequest(rest)
	case "approve":
		err = exemptionDecide(rest, "ApproveExemption")
	case "reject":
		err = exemptionDecide(rest, "RejectExemption")
	case "revoke":
		err = exemptionRevoke(rest)
	case "get":
		err = exemptionGet(rest)
	case "list":
		err = exemptionList(rest)
	case "audit":
		err = exemptionAudit(rest)
	default:
		exemptionUsage()
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func exemptionUsage() {
	fmt.Fprintf(os.Stderr, `usage:
  compatcheck exemption request -pkg P -base v1 -head v2 -fingerprint FP \
      -owner PERSON -reason TEXT -consumer C [-consumer C2] -expires RFC3339 \
      [-by APPLICANT] [-server URL]
  compatcheck exemption approve -id N -expected-version V [-by APPROVER] [-server URL]
  compatcheck exemption reject  -id N -expected-version V [-by ACTOR] [-server URL]
  compatcheck exemption revoke  -id N -expected-version V [-reason TEXT] [-by ACTOR] [-server URL]
  compatcheck exemption get     -id N [-server URL]
  compatcheck exemption list    -pkg P [-fingerprint FP] [-server URL]
  compatcheck exemption audit   -pkg P [-id N] [-server URL]
`)
}

func serverFlags(fs *flag.FlagSet) (server, actor *string) {
	server = fs.String("server", "", "registry base URL (default $REGISTRY_URL or http://localhost:8080)")
	actor = fs.String("by", "", "acting identity (default $REGISTRY_ACTOR)")
	return server, actor
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func exemptionRequest(args []string) error {
	fs := flag.NewFlagSet("exemption request", flag.ContinueOnError)
	pkg := fs.String("pkg", "", "package name")
	base := fs.String("base", "", "base version of the report")
	head := fs.String("head", "", "head version of the report")
	fp := fs.String("fingerprint", "", "finding fingerprint")
	idx := fs.Int("finding-index", -1, "0-based index into stored report findings (alternative to -fingerprint)")
	owner := fs.String("owner", "", "responsible person")
	reason := fs.String("reason", "", "justification")
	consumer := multiFlag{}
	fs.Var(&consumer, "consumer", "consumer this exemption applies to (repeatable; never global)")
	expires := fs.String("expires", "", "RFC3339 expiry instant (exclusive boundary)")
	server, actor := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" || *base == "" || *head == "" || *owner == "" || *reason == "" || *expires == "" || len(consumer) == 0 {
		exemptionUsage()
		return fmt.Errorf("pkg, base, head, owner, reason, expires and at least one consumer are required")
	}
	c := newRegistryClient(*server, *actor)
	body := map[string]any{
		"package": *pkg, "base_version": *base, "head_version": *head,
		"owner": *owner, "reason": *reason, "consumers": []string(consumer),
		"expires_at": *expires,
	}
	if *fp != "" {
		body["fingerprint"] = *fp
	}
	if *idx >= 0 {
		body["finding_index"] = *idx
	}
	if *actor != "" {
		body["requested_by"] = *actor
	}
	out, err := c.call("/registry.v1.Registry/RequestExemption", body)
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func exemptionDecide(args []string, rpc string) error {
	fs := flag.NewFlagSet("exemption "+strings.ToLower(rpc), flag.ContinueOnError)
	id := fs.Int64("id", 0, "exemption id")
	version := fs.Int64("expected-version", 0, "optimistic-concurrency version read earlier")
	server, actor := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("-id is required")
	}
	c := newRegistryClient(*server, *actor)
	out, err := c.call("/registry.v1.Registry/"+rpc, map[string]any{
		"id": *id, "expected_version": *version, "actor": c.actor,
	})
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func exemptionRevoke(args []string) error {
	fs := flag.NewFlagSet("exemption revoke", flag.ContinueOnError)
	id := fs.Int64("id", 0, "exemption id")
	version := fs.Int64("expected-version", 0, "optimistic-concurrency version read earlier")
	reason := fs.String("reason", "", "revocation reason")
	server, actor := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("-id is required")
	}
	c := newRegistryClient(*server, *actor)
	out, err := c.call("/registry.v1.Registry/RevokeExemption", map[string]any{
		"id": *id, "expected_version": *version, "actor": c.actor, "reason": *reason,
	})
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func exemptionGet(args []string) error {
	fs := flag.NewFlagSet("exemption get", flag.ContinueOnError)
	id := fs.Int64("id", 0, "exemption id")
	server, _ := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("-id is required")
	}
	c := newRegistryClient(*server, "")
	out, err := c.call("/registry.v1.Registry/GetExemption", map[string]any{"id": *id})
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func exemptionList(args []string) error {
	fs := flag.NewFlagSet("exemption list", flag.ContinueOnError)
	pkg := fs.String("pkg", "", "package name")
	fp := fs.String("fingerprint", "", "filter by finding fingerprint")
	server, _ := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" {
		return fmt.Errorf("-pkg is required")
	}
	c := newRegistryClient(*server, "")
	out, err := c.call("/registry.v1.Registry/ListExemptions", map[string]any{
		"package": *pkg, "fingerprint": *fp,
	})
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func exemptionAudit(args []string) error {
	fs := flag.NewFlagSet("exemption audit", flag.ContinueOnError)
	pkg := fs.String("pkg", "", "package name")
	id := fs.Int64("id", 0, "narrow to one exemption id")
	server, _ := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" {
		return fmt.Errorf("-pkg is required")
	}
	c := newRegistryClient(*server, "")
	out, err := c.call("/registry.v1.Registry/ListAuditEvents", map[string]any{
		"package": *pkg, "exemption_id": *id,
	})
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

// multiFlag collects a repeated string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
