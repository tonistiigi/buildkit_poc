// +build windows

package cache

import (
	"context"

	"github.com/moby/buildkit/session"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func (sr *immutableRef) computeOverlayBlob(ctx context.Context, mediaType string, ref string, s session.Group) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}
