package workercontext

import (
	"context"

	"google.golang.org/grpc/metadata"
)

const metadataKey = "buildkit-worker"

func WithWorker(ctx context.Context, id string) context.Context {
	if id != "" {
		return metadata.AppendToOutgoingContext(ctx, metadataKey, id)
	}
	return ctx
}

func Worker(ctx context.Context) string {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		if ss := md[metadataKey]; len(ss) > 0 && ss[0] != "" {
			return ss[0]
		}
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ss := md[metadataKey]; len(ss) > 0 && ss[0] != "" {
			return ss[0]
		}
	}
	return ""
}
