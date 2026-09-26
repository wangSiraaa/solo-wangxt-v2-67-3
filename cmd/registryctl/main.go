// Command registryctl is the CLI front-end for the registry service's
// exemption workflow and exemption-aware compatibility checks. It talks
// to a running server over the connect protocol's JSON codec; there is
// deliberately no web UI.
//
//	registryctl -addr http://localhost:8080 check   -pkg P -base V1 [-head V2] [-consumer C]
//	registryctl -addr http://localhost:8080 request -pkg P -base V1 -head V2 -fingerprint F \
//	    -owner O -reason R -consumer C [-consumer C2] -expires 2026-10-01T00:00:00Z -by alice
//	registryctl -addr http://localhost:8080 approve -id ex_... -version 1 -by bob
//	registryctl -addr http://localhost:8080 revoke  -id ex_... -version 2 -by carol [-reason R]
//	registryctl -addr http://localhost:8080 list    -pkg P [-all]
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
	"time"
)

const servicePrefix = "/registry.v1.Registry/"

func main() {
	fs := flag.NewFlagSet("registryctl", flag.ExitOnError)
	addr := fs.String("addr", envOr("REGISTRY_ADDR", "http://localhost:8080"), "registry service base URL")
	fs.Usage = usage
	_ = fs.Parse(os.Args[1:])
	if fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	c := &client{addr: strings.TrimRight(*addr, "/")}

	var err error
	switch fs.Arg(0) {
	case "check":
		err = c.cmdCheck(fs.Args()[1:])
	case "request":
		err = c.cmdRequest(fs.Args()[1:])
	case "approve":
		err = c.cmdTransition(fs.Args()[1:], "ApproveExemption")
	case "revoke":
		err = c.cmdTransition(fs.Args()[1:], "RevokeExemption")
	case "list":
		err = c.cmdList(fs.Args()[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: registryctl [-addr URL] <command> [flags]

commands:
  check     run CheckCompatibility and print the report plus the release decision
  request   file a PENDING exemption for one finding of a stored report
  approve   approve a pending exemption (must not be the requester)
  revoke    revoke an exemption; blocking resumes immediately
  list      list exemptions of a package

run 'registryctl <command> -h' for command flags
`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type client struct{ addr string }

// post calls one procedure and decodes the JSON response into out.
func (c *client) post(procedure string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(c.addr+servicePrefix+procedure, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &e) == nil && e.Message != "" {
			return fmt.Errorf("%s: %s", e.Code, e.Message)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// stringList collects a repeated flag: -consumer a -consumer b.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func (c *client) cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	pkg := fs.String("pkg", "", "package name (required)")
	base := fs.String("base", "", "base version (required)")
	head := fs.String("head", "", "candidate version to compare against base (required)")
	consumer := fs.String("consumer", "", "evaluate for this consumer")
	_ = fs.Parse(args)
	if *pkg == "" || *base == "" || *head == "" {
		return fmt.Errorf("check requires -pkg, -base and -head")
	}
	var out json.RawMessage
	err := c.post("CheckCompatibility", map[string]any{
		"package":           *pkg,
		"base_version":      *base,
		"candidate_version": *head,
		"consumer":          *consumer,
	}, &out)
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func (c *client) cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	pkg := fs.String("pkg", "", "package name (required)")
	base := fs.String("base", "", "base version of the report (required)")
	head := fs.String("head", "", "head version of the report (required)")
	fingerprint := fs.String("fingerprint", "", "finding fingerprint from the report (required)")
	owner := fs.String("owner", "", "exemption owner (required)")
	reason := fs.String("reason", "", "justification (required)")
	by := fs.String("by", "", "requester identity (required)")
	expires := fs.String("expires", "", "expiry time, RFC3339 (required)")
	requestID := fs.String("request-id", "", "idempotency key; safe retries reuse it")
	var consumers stringList
	fs.Var(&consumers, "consumer", "affected consumer; repeat for several, or \"*\" for all (required)")
	_ = fs.Parse(args)
	if *pkg == "" || *base == "" || *head == "" || *fingerprint == "" || *owner == "" || *reason == "" || *by == "" || *expires == "" || len(consumers) == 0 {
		fs.Usage()
		return fmt.Errorf("request requires -pkg, -base, -head, -fingerprint, -owner, -reason, -by, -expires and at least one -consumer")
	}
	if _, err := time.Parse(time.RFC3339, *expires); err != nil {
		return fmt.Errorf("-expires must be RFC3339: %v", err)
	}
	var out json.RawMessage
	err := c.post("RequestExemption", map[string]any{
		"package":      *pkg,
		"base_version": *base,
		"head_version": *head,
		"fingerprint":  *fingerprint,
		"owner":        *owner,
		"reason":       *reason,
		"consumers":    consumers,
		"expires_at":   *expires,
		"requested_by": *by,
		"request_id":   *requestID,
	}, &out)
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}

// cmdTransition implements approve and revoke; both are version-guarded
// optimistic-concurrency transitions.
func (c *client) cmdTransition(args []string, procedure string) error {
	name := strings.TrimSuffix(procedure, "Exemption")
	fs := flag.NewFlagSet(strings.ToLower(name), flag.ExitOnError)
	id := fs.String("id", "", "exemption id (required)")
	version := fs.Int64("version", 0, "expected exemption version (required)")
	by := fs.String("by", "", "actor identity (required)")
	reason := fs.String("reason", "", "revocation reason")
	_ = fs.Parse(args)
	if *id == "" || *version == 0 || *by == "" {
		fs.Usage()
		return fmt.Errorf("%s requires -id, -version and -by", strings.ToLower(name))
	}
	body := map[string]any{
		"id":               *id,
		"expected_version": *version,
	}
	if procedure == "ApproveExemption" {
		body["approver"] = *by
	} else {
		body["revoker"] = *by
		body["reason"] = *reason
	}
	var out json.RawMessage
	if err := c.post(procedure, body, &out); err != nil {
		return err
	}
	printJSON(out)
	return nil
}

func (c *client) cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	pkg := fs.String("pkg", "", "package name (required)")
	all := fs.Bool("all", false, "include pending, expired and revoked exemptions")
	_ = fs.Parse(args)
	if *pkg == "" {
		return fmt.Errorf("list requires -pkg")
	}
	var out json.RawMessage
	err := c.post("ListExemptions", map[string]any{
		"package":          *pkg,
		"include_inactive": *all,
	}, &out)
	if err != nil {
		return err
	}
	printJSON(out)
	return nil
}
