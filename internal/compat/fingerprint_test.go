package compat

import "testing"

func TestFindingFingerprintPositionIndependent(t *testing.T) {
	f := Finding{
		Code: "FIELD_TYPE_CHANGED", Severity: SeverityFail, Dimension: DimensionBoth,
		Message: "acme.pay.Invoice", Path: "total",
		Detail: "changed type int32 -> int64",
	}
	base := FindingFingerprint("acme.pay", f)

	// Presentation and verdict changes must not move the fingerprint.
	variants := []Finding{
		{Code: f.Code, Severity: SeverityWarn, Dimension: f.Dimension, Message: f.Message, Path: f.Path, Detail: "different severity"},
		{Code: f.Code, Severity: f.Severity, Dimension: f.Dimension, Message: f.Message, Path: f.Path, Detail: "rewritten detail text"},
	}
	for i, v := range variants {
		if got := FindingFingerprint("acme.pay", v); got != base {
			t.Fatalf("variant %d fingerprint = %s, want stable %s", i, got, base)
		}
	}

	// Any rule/object/dimension change must produce a different fingerprint.
	changes := []Finding{
		{Code: "FIELD_NUMBER_REUSED", Severity: f.Severity, Dimension: f.Dimension, Message: f.Message, Path: f.Path},
		{Code: f.Code, Severity: f.Severity, Dimension: f.Dimension, Message: "acme.pay.Other", Path: f.Path},
		{Code: f.Code, Severity: f.Severity, Dimension: f.Dimension, Message: f.Message, Path: "amount"},
		{Code: f.Code, Severity: f.Severity, Dimension: DimensionWire, Message: f.Message, Path: f.Path},
	}
	for i, c := range changes {
		if got := FindingFingerprint("acme.pay", c); got == base {
			t.Fatalf("change %d unexpectedly kept fingerprint %s", i, base)
		}
	}

	// The same finding in another package namespace is distinct.
	if FindingFingerprint("acme.other", f) == base {
		t.Fatal("fingerprint must be package-scoped")
	}
}
