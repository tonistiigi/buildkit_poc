package contentutil

import (
	"bytes"
	"testing"

	"github.com/moby/buildkit/util/testutil"

	"github.com/containerd/containerd/content"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t)

	b0 := NewBuffer()
	b1 := NewBuffer()

	err := content.WriteBlob(ctx, b0, "foo", bytes.NewBuffer([]byte("foobar")), ocispec.Descriptor{Size: -1})
	require.NoError(t, err)

	err = Copy(ctx, b1, b0, ocispec.Descriptor{Digest: digest.FromBytes([]byte("foobar")), Size: -1})
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, b1, ocispec.Descriptor{Digest: digest.FromBytes([]byte("foobar"))})
	require.NoError(t, err)
	require.Equal(t, string(dt), "foobar")
}
