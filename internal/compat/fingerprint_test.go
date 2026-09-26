package compat

import "testing"

// The fingerprint is the semantic identity of a finding: stable against
// prose changes, sensitive to the rule and the object.
func TestFindingFingerprint(t *testing.T) {
	base := Finding{
		Code: "FIELD_TYPE_CHANGED", Severity: SeverityFail, Dimension: DimensionBoth,
		Message: "acme.pay.Invoice", Path: "total",
		Detail: "field total changed from int32 to int64",
	}

	same := base
	same.Detail = "completely reworded prose, e.g. after a line shift"
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("detail prose must not affect the fingerprint")
	}

	variants := map[string]Finding{
		"rule changed":      {Code: "FIELD_REMOVED_UNRESERVED", Severity: base.Severity, Dimension: base.Dimension, Message: base.Message, Path: base.Path},
		"object moved":      {Code: base.Code, Severity: base.Severity, Dimension: base.Dimension, Message: base.Message, Path: "amount"},
		"message changed":   {Code: base.Code, Severity: base.Severity, Dimension: base.Dimension, Message: "acme.pay.Receipt", Path: base.Path},
		"severity changed":  {Code: base.Code, Severity: SeverityWarn, Dimension: base.Dimension, Message: base.Message, Path: base.Path},
		"dimension changed": {Code: base.Code, Severity: base.Severity, Dimension: DimensionJSON, Message: base.Message, Path: base.Path},
	}
	for name, v := range variants {
		if v.Fingerprint() == base.Fingerprint() {
			t.Fatalf("%s must change the fingerprint", name)
		}
	}

	// No field-order ambiguity: different field splits never collide.
	a := Finding{Code: "AB", Message: "C"}
	b := Finding{Code: "A", Message: "BC"}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("length-prefixing must prevent field-boundary collisions")
	}
}
