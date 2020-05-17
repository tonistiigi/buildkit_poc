package llb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrontendMarshal(t *testing.T) {
	t.Parallel()

	input := Git("remote", "ref")
	inputDef, err := input.Marshal()
	require.NoError(t, err)

	st := Frontend(Image("foo"), WithFrontendInput("mykey", input), WithFrontendOpt("myopt", "bar"))

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
	require.Equal(t, 0, int(b.Builder))
	require.Equal(t, 0, len(b.Inputs))
	require.Equal(t, 1, len(b.Defs))
	require.NotNil(t, b.Defs["mykey"])

	for i, dt := range b.Defs["mykey"].Def {
		require.Equal(t, inputDef.Def[i], dt)
	}

	for dgst, meta := range b.Defs["mykey"].Metadata {
		require.Equal(t, inputDef.Metadata[dgst], meta)
	}
}
