package llb

import (
	"testing"

	"github.com/moby/buildkit/solver/pb"
	"github.com/stretchr/testify/require"
)

func TestBuildMarshal(t *testing.T) {
	t.Parallel()

	st := Build(HTTP("foo"), WithFilename("myfilename"))

	def, err := st.Marshal()
	require.NoError(t, err)

	m, arr := parseDef(t, def.Def)
	require.Equal(t, 3, len(arr))

	dgst, idx := last(t, arr)
	require.Equal(t, 0, idx)
	require.Equal(t, m[dgst], arr[1])

	require.Equal(t, len(arr[1].Inputs), 1)
	require.Equal(t, m[arr[1].Inputs[0].Digest], arr[0])
	require.Equal(t, 0, int(arr[1].Inputs[0].Index))

	b := arr[1].GetBuild()
	require.NotEqual(t, nil, b)
	require.Equal(t, pb.LLBBuilder, b.Builder)
	require.Equal(t, &pb.BuildInput{Input: pb.InputIndex(0)}, b.Inputs[pb.LLBDefinitionInput])
	require.Equal(t, "myfilename", b.Attrs[pb.AttrLLBDefinitionFilename])
}
