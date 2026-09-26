package compat

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// FindingFingerprint is the stable, position-independent identity of a
// finding. It deliberately excludes the source line, the human-readable
// detail text and the severity: moving a declaration to another line must
// not invalidate an exemption, whereas a different rule (code), a change
// of the affected object (message/path) or a different dimension yields a
// different fingerprint and forces a fresh exemption request.
func FindingFingerprint(pkg string, f Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		pkg,
		f.Code,
		f.Message,
		f.Path,
		string(f.Dimension),
	}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// SourceLines resolves the best-effort 1-based source line of every
// finding, aligned with report.Findings. Lines are presentation-only:
// they never feed FindingFingerprint and are never persisted with the
// immutable report. New descriptors are preferred (a line-only move in
// the new schema is visible that way); removed members only exist in the
// old set, which is the fallback.
func SourceLines(report *Report, oldFiles, newFiles *protoregistry.Files) []int {
	lines := make([]int, len(report.Findings))
	for i, f := range report.Findings {
		if f.Message == "" {
			continue // file- and package-level findings have no member location
		}
		if line := findingLine(newFiles, f); line != 0 {
			lines[i] = line
			continue
		}
		lines[i] = findingLine(oldFiles, f)
	}
	return lines
}

func findingLine(files *protoregistry.Files, f Finding) int {
	if files == nil {
		return 0
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(f.Message))
	if err != nil {
		return 0
	}
	var fd protoreflect.FileDescriptor
	var locDesc protoreflect.Descriptor
	switch t := d.(type) {
	case protoreflect.MessageDescriptor:
		fd = t.ParentFile()
		locDesc = fieldOrOneof(t, f.Path)
		if locDesc == nil {
			locDesc = t
		}
	case protoreflect.EnumDescriptor:
		fd = t.ParentFile()
		locDesc = t
	default:
		return 0
	}
	loc := fd.SourceLocations().ByDescriptor(locDesc)
	if len(loc.Path) == 0 {
		return 0
	}
	return int(loc.StartLine) + 1
}

// fieldOrOneof resolves the first path segment of a field path ("amount",
// "lines[2].amount" -> lines) to a field descriptor, falling back to a
// oneof descriptor for oneof-level findings.
func fieldOrOneof(md protoreflect.MessageDescriptor, path string) protoreflect.Descriptor {
	if path == "" {
		return md
	}
	seg := path
	for _, sep := range []string{".", "["} {
		if i := strings.Index(seg, sep); i >= 0 {
			seg = seg[:i]
		}
	}
	if f := md.Fields().ByName(protoreflect.Name(seg)); f != nil {
		return f
	}
	if oo := md.Oneofs().ByName(protoreflect.Name(seg)); oo != nil {
		return oo
	}
	return md
}
