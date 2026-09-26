package registry

import (
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"
)

// Service procedure paths, matching api/registry/v1/registry.proto.
const (
	ProcedureRegisterVersion    = "/registry.v1.Registry/RegisterVersion"
	ProcedureCheckCompatibility = "/registry.v1.Registry/CheckCompatibility"
	ProcedureDeclareConsumer    = "/registry.v1.Registry/DeclareConsumer"
	ProcedureListVersions       = "/registry.v1.Registry/ListVersions"
	ProcedureRequestExemption   = "/registry.v1.Registry/RequestExemption"
	ProcedureApproveExemption   = "/registry.v1.Registry/ApproveExemption"
	ProcedureRevokeExemption    = "/registry.v1.Registry/RevokeExemption"
	ProcedureListExemptions     = "/registry.v1.Registry/ListExemptions"
)

// jsonCodec speaks application/json for plain Go structs, so the service
// needs no code generation step while remaining a first-class ConnectRPC
// endpoint (connect protocol, and gRPC/gRPC-Web with the json sub-codec).
type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }

func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// Handler returns the HTTP handler for the registry service.
func (s *Service) Handler() (string, http.Handler) {
	mux := http.NewServeMux()
	mux.Handle(ProcedureRegisterVersion, connect.NewUnaryHandler(
		ProcedureRegisterVersion, s.RegisterVersion, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureCheckCompatibility, connect.NewUnaryHandler(
		ProcedureCheckCompatibility, s.CheckCompatibility, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureDeclareConsumer, connect.NewUnaryHandler(
		ProcedureDeclareConsumer, s.DeclareConsumer, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureListVersions, connect.NewUnaryHandler(
		ProcedureListVersions, s.ListVersions, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureRequestExemption, connect.NewUnaryHandler(
		ProcedureRequestExemption, s.RequestExemption, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureApproveExemption, connect.NewUnaryHandler(
		ProcedureApproveExemption, s.ApproveExemption, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureRevokeExemption, connect.NewUnaryHandler(
		ProcedureRevokeExemption, s.RevokeExemption, connect.WithCodec(jsonCodec{})))
	mux.Handle(ProcedureListExemptions, connect.NewUnaryHandler(
		ProcedureListExemptions, s.ListExemptions, connect.WithCodec(jsonCodec{})))
	return "/registry.v1.Registry/", mux
}
