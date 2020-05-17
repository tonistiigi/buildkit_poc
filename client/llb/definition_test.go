package llb

import (
	"bytes"
	"context"
	"testing"

	"github.com/containerd/containerd/platforms"
	"github.com/stretchr/testify/require"
)

func TestDefinitionEquivalence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
	}{
		{"scratch", Scratch()},
		{"image op", Image("ref")},
		{"exec op", Image("ref").Run(Shlex("args")).Root()},
		{"local op", Local("name")},
		{"git op", Git("remote", "ref")},
		{"http op", HTTP("url")},
		{"file op", Scratch().File(Mkdir("foo", 0600).Mkfile("foo/bar", 0600, []byte("data")).Copy(Scratch(), "src", "dst"))},
		{"platform constraint", Image("ref", LinuxArm64)},
		{"mount", Image("busybox").Run(Shlex(`sh -c "echo foo > /out/foo"`)).AddMount("/out", Scratch())},
		{"frontend scratch op", Frontend(Scratch())},
		{"frontend op", Frontend(Image("ref"), WithFrontendInput("key", Git("remote", "ref")), WithFrontendOpt("key", "value"))},
		{"build scratch op", Build(Scratch())},
		{"build op", Build(Image("ref"), WithFilename("filename"))},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.TODO()

			def, err := tc.state.Marshal(context.TODO())
			require.NoError(t, err)

			op, err := NewDefinitionOp(def.ToPB())
			require.NoError(t, err)

			err = op.Validate(ctx)
			require.NoError(t, err)

			st2 := NewState(op.Output())

			def2, err := st2.Marshal(context.TODO())
			require.NoError(t, err)
			require.Equal(t, len(def.Def), len(def2.Def))
			require.Equal(t, len(def.Metadata), len(def2.Metadata))

			for i := 0; i < len(def.Def); i++ {
				res := bytes.Compare(def.Def[i], def2.Def[i])
				require.Equal(t, res, 0)
			}

			for dgst := range def.Metadata {
				require.Equal(t, def.Metadata[dgst], def2.Metadata[dgst])
			}

			expectedPlatform, err := tc.state.GetPlatform(ctx)
			require.NoError(t, err)
			actualPlatform, err := st2.GetPlatform(ctx)
			require.NoError(t, err)

			if expectedPlatform == nil && actualPlatform != nil {
				defaultPlatform := platforms.Normalize(platforms.DefaultSpec())
				expectedPlatform = &defaultPlatform
			}

			require.Equal(t, expectedPlatform, actualPlatform)
		})
	}
}
