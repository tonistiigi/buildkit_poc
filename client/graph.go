package client

import (
	"time"

	digest "github.com/opencontainers/go-digest"
	controlapi "github.com/moby/buildkit/api/services/control"
)

type Vertex struct {
	Digest    digest.Digest
	Inputs    []digest.Digest
	Name      string
	Started   *time.Time
	Completed *time.Time
	Cached    bool
	Error     string
}

type VertexStatus struct {
	ID        string
	Vertex    digest.Digest
	Name      string
	Total     int64
	Current   int64
	Timestamp time.Time
	Started   *time.Time
	Completed *time.Time
}

type VertexLog struct {
	Vertex    digest.Digest
	Stream    int
	Data      []byte
	Timestamp time.Time
}

type SolveStatus struct {
	Vertexes []*Vertex
	Statuses []*VertexStatus
	Logs     []*VertexLog
}

type SolveResponse struct {
	// ExporterResponse is also used for CacheExporter
	ExportersResponse []*controlapi.ExporterResponse
}
