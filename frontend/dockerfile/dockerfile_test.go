package dockerfile

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/dockerfile/builder"
	"github.com/moby/buildkit/frontend/dockerfile/dockerfile2llb"
	gateway "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/upload/uploadprovider"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/testutil"
	"github.com/moby/buildkit/util/testutil/httpserver"
	"github.com/moby/buildkit/util/testutil/integration"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func init() {
	if os.Getenv("TEST_DOCKERD") == "1" {
		integration.InitDockerdWorker()
	} else {
		integration.InitOCIWorker()
		integration.InitContainerdWorker()
	}
}

var allTests = []integration.Test{
	testCmdShell,
	testGlobalArg,
	testDockerfileDirs,
	testDockerfileInvalidCommand,
	testDockerfileADDFromURL,
	testDockerfileAddArchive,
	testDockerfileScratchConfig,
	testExportedHistory,
	testExposeExpansion,
	testUser,
	testCacheReleased,
	testDockerignore,
	testDockerignoreInvalid,
	testDockerfileFromGit,
	testMultiStageImplicitFrom,
	testMultiStageCaseInsensitive,
	testLabels,
	testCacheImportExport,
	testReproducibleIDs,
	testImportExportReproducibleIDs,
	testNoCache,
	testDockerfileFromHTTP,
	testBuiltinArgs,
	testPullScratch,
	testSymlinkDestination,
	testHTTPDockerfile,
	testPlatformArgsImplicit,
	testPlatformArgsExplicit,
	testExportMultiPlatform,
	testQuotedMetaArgs,
	testIgnoreEntrypoint,
	testSymlinkedDockerfile,
	testDockerfileAddArchiveWildcard,
	testEmptyWildcard,
	testWorkdirCreatesDir,
	testDockerfileAddArchiveWildcard,
	testCopyChownExistingDir,
	testCopyWildcardCache,
	testDockerignoreOverride,
	testTarExporter,
	testDefaultEnvWithArgs,
	testEnvEmptyFormatting,
	testCacheMultiPlatformImportExport,
	testOnBuildCleared,
	testFrontendUseForwardedSolveResults,
	testFrontendInputs,
	testNestedDockerfileBuild,
}

var fileOpTests = []integration.Test{
	testEmptyDestDir,
	testCopyChownCreateDest,
	testCopyThroughSymlinkContext,
	testCopyThroughSymlinkMultiStage,
	testCopySocket,
	testContextChangeDirToFile,
	testNoSnapshotLeak,
	testCopySymlinks,
	testCopyChown,
	testCopyOverrideFiles,
	testCopyVarSubstitution,
	testCopyWildcards,
	testCopyRelative,
	testTarContext,
	testTarContextExternalDockerfile,
	testWorkdirUser,
	testWorkdirExists,
	testWorkdirCopyIgnoreRelative,
	testCopyFollowAllSymlinks,
	testDockerfileAddChownExpand,
}

// Tests that depend on the `security.*` entitlements
var securityTests = []integration.Test{}

// Tests that depend on the `network.*` entitlements
var networkTests = []integration.Test{}

var opts []integration.TestOpt
var securityOpts []integration.TestOpt

type frontend interface {
	Solve(context.Context, *client.Client, client.SolveOpt, chan *client.SolveStatus) (*client.SolveResponse, error)
	DFCmdArgs(string, string) (string, string)
	RequiresBuildctl(t *testing.T)
}

var dockerfileFrontend string

func init() {
	frontends := map[string]interface{}{}

	opts = []integration.TestOpt{
		integration.WithMirroredImages(integration.OfficialImages("busybox:latest")),
		integration.WithMirroredImages(map[string]string{
			"docker/dockerfile-copy:v0.1.9": "docker.io/" + dockerfile2llb.DefaultCopyImage,
		}),
		integration.WithMatrix("frontend", frontends),
	}

	if os.Getenv("FRONTEND_BUILTIN_ONLY") == "1" {
		frontends["builtin"] = &builtinFrontend{}
	} else if os.Getenv("FRONTEND_CLIENT_ONLY") == "1" {
		frontends["client"] = &clientFrontend{}
	} else if gw := os.Getenv("FRONTEND_GATEWAY_ONLY"); gw != "" {
		name := "buildkit_test/" + identity.NewID() + ":latest"
		opts = append(opts, integration.WithMirroredImages(map[string]string{
			name: gw,
		}))
		frontends["gateway"] = &gatewayFrontend{gw: name}
		dockerfileFrontend = name
	} else {
		frontends["builtin"] = &builtinFrontend{}
		frontends["client"] = &clientFrontend{}
	}
}

func TestIntegration(t *testing.T) {
	integration.Run(t, allTests, opts...)
	integration.Run(t, fileOpTests, append(opts, integration.WithMatrix("fileop", map[string]interface{}{
		"true":  true,
		"false": false,
	}))...)
	integration.Run(t, securityTests, append(append(opts, securityOpts...),
		integration.WithMatrix("security.insecure", map[string]interface{}{
			"granted": securityInsecureGranted,
			"denied":  securityInsecureDenied,
		}))...)
	integration.Run(t, networkTests, append(opts,
		integration.WithMatrix("network.host", map[string]interface{}{
			"granted": networkHostGranted,
			"denied":  networkHostDenied,
		}))...)
}

func testDefaultEnvWithArgs(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build
ARG my_arg
ENV my_arg "my_arg=${my_arg:-def_val}"
COPY myscript.sh myscript.sh
RUN ./myscript.sh $my_arg
FROM scratch
COPY --from=build /out /out
`)

	script := []byte(`
#!/usr/bin/env sh
echo -n $my_arg $1 > /out
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("myscript.sh", script, 0700),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	for _, x := range []struct {
		name          string
		frontendAttrs map[string]string
		expected      string
	}{
		{"nil", nil, "my_arg=def_val my_arg=def_val"},
		{"empty", map[string]string{"build-arg:my_arg": ""}, "my_arg=def_val my_arg=def_val"},
		{"override", map[string]string{"build-arg:my_arg": "override"}, "my_arg=override my_arg=override"},
	} {
		t.Run(x.name, func(t *testing.T) {
			_, err = f.Solve(context.TODO(), c, client.SolveOpt{
				FrontendAttrs: x.frontendAttrs,
				Exports: []client.ExportEntry{
					{
						Type:      client.ExporterLocal,
						OutputDir: destDir,
					},
				},
				LocalDirs: map[string]string{
					builder.DefaultLocalNameDockerfile: dir,
					builder.DefaultLocalNameContext:    dir,
				},
			}, nil)
			require.NoError(t, err)

			dt, err := ioutil.ReadFile(filepath.Join(destDir, "out"))
			require.NoError(t, err)
			require.Equal(t, x.expected, string(dt))
		})
	}
}

func testEnvEmptyFormatting(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build
ENV myenv foo%sbar
RUN [ "$myenv" = 'foo%sbar' ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testDockerignoreOverride(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	dockerfile := []byte(`
FROM busybox
COPY . .
RUN [ -f foo ] && [ ! -f bar ]
`)

	ignore := []byte(`
bar
`)

	dockerfile2 := []byte(`
FROM busybox
COPY . .
RUN [ ! -f foo ] && [ -f bar ]
`)

	ignore2 := []byte(`
foo
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("Dockerfile.dockerignore", ignore, 0600),
		fstest.CreateFile("Dockerfile2", dockerfile2, 0600),
		fstest.CreateFile("Dockerfile2.dockerignore", ignore2, 0600),
		fstest.CreateFile("foo", []byte("contents0"), 0600),
		fstest.CreateFile("bar", []byte("contents0"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"filename": "Dockerfile2",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testEmptyDestDir(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
ENV empty=""
COPY testfile $empty
RUN [ "$(cat testfile)" == "contents0" ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("testfile", []byte("contents0"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testTarExporter(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch AS stage-linux
COPY foo forlinux

FROM scratch AS stage-darwin
COPY bar fordarwin

FROM stage-$TARGETOS
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("data"), 0600),
		fstest.CreateFile("bar", []byte("data2"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	buf := &bytes.Buffer{}
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:   client.ExporterTar,
				Output: fixedWriteCloser(&nopWriteCloser{buf}),
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(buf.Bytes(), false)
	require.NoError(t, err)

	mi, ok := m["forlinux"]
	require.Equal(t, true, ok)
	require.Equal(t, "data", string(mi.Data))

	// repeat multi-platform
	buf = &bytes.Buffer{}
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:   client.ExporterTar,
				Output: fixedWriteCloser(&nopWriteCloser{buf}),
			},
		},
		FrontendAttrs: map[string]string{
			"platform": "linux/amd64,darwin/amd64",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	m, err = testutil.ReadTarToMap(buf.Bytes(), false)
	require.NoError(t, err)

	mi, ok = m["linux_amd64/forlinux"]
	require.Equal(t, true, ok)
	require.Equal(t, "data", string(mi.Data))

	mi, ok = m["darwin_amd64/fordarwin"]
	require.Equal(t, true, ok)
	require.Equal(t, "data2", string(mi.Data))
}

func testWorkdirCreatesDir(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
WORKDIR /foo
WORKDIR /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	fi, err := os.Lstat(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, true, fi.IsDir())
}

func testCacheReleased(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)
}

func testSymlinkedDockerfile(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
ENV foo bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile.web", dockerfile, 0600),
		fstest.Symlink("Dockerfile.web", "Dockerfile"),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testCopyChownExistingDir(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
# Set up files and directories with known ownership
FROM busybox AS source
RUN touch /file && chown 100:200 /file \
 && mkdir -p /dir/subdir \
 && touch /dir/subdir/nestedfile \
 && chown 100:200 /dir \
 && chown 101:201 /dir/subdir \
 && chown 102:202 /dir/subdir/nestedfile

FROM busybox AS test_base
RUN mkdir -p /existingdir/existingsubdir \
 && touch /existingdir/existingfile \
 && chown 500:600 /existingdir \
 && chown 501:601 /existingdir/existingsubdir \
 && chown 501:601 /existingdir/existingfile


# Copy files from the source stage
FROM test_base AS copy_from
COPY --from=source /file .
# Copy to a non-existing target directory creates the target directory (as root), then copies the _contents_ of the source directory into it
COPY --from=source /dir /dir
# Copying to an existing target directory will copy the _contents_ of the source directory into it
COPY --from=source /dir/. /existingdir

RUN e="100:200"; p="/file"                         ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="0:0";     p="/dir"                          ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="101:201"; p="/dir/subdir"                   ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="102:202"; p="/dir/subdir/nestedfile"        ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
# Existing files and directories ownership should not be modified
 && e="500:600"; p="/existingdir"                  ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="501:601"; p="/existingdir/existingsubdir"   ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="501:601"; p="/existingdir/existingfile"     ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
# But new files and directories should maintain their ownership
 && e="101:201"; p="/existingdir/subdir"           ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="102:202"; p="/existingdir/subdir/nestedfile"; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi


# Copy files from the source stage and chown them.
FROM test_base AS copy_from_chowned
COPY --from=source --chown=300:400 /file .
# Copy to a non-existing target directory creates the target directory (as root), then copies the _contents_ of the source directory into it
COPY --from=source --chown=300:400 /dir /dir
# Copying to an existing target directory copies the _contents_ of the source directory into it
COPY --from=source --chown=300:400 /dir/. /existingdir

RUN e="300:400"; p="/file"                         ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="300:400"; p="/dir"                          ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="300:400"; p="/dir/subdir"                   ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="300:400"; p="/dir/subdir/nestedfile"        ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
# Existing files and directories ownership should not be modified
 && e="500:600"; p="/existingdir"                  ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="501:601"; p="/existingdir/existingsubdir"   ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="501:601"; p="/existingdir/existingfile"     ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
# But new files and directories should be chowned
 && e="300:400"; p="/existingdir/subdir"           ; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi \
 && e="300:400"; p="/existingdir/subdir/nestedfile"; a=` + "`" + `stat -c "%u:%g" "$p"` + "`" + `; if [ "$a" != "$e" ]; then echo "incorrect ownership on $p. expected $e, got $a"; exit 1; fi
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile.web", dockerfile, 0600),
		fstest.Symlink("Dockerfile.web", "Dockerfile"),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"target": "copy_from",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testCopyWildcardCache(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS base
COPY foo* files/
RUN cat /dev/urandom | head -c 100 | sha256sum > unique
COPY bar files/
FROM scratch
COPY --from=base unique /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo1", []byte("foo1-data"), 0600),
		fstest.CreateFile("foo2", []byte("foo2-data"), 0600),
		fstest.CreateFile("bar", []byte("bar-data"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)

	err = ioutil.WriteFile(filepath.Join(dir, "bar"), []byte("bar-data-mod"), 0600)
	require.NoError(t, err)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt2, err := ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)
	require.Equal(t, string(dt), string(dt2))

	err = ioutil.WriteFile(filepath.Join(dir, "foo2"), []byte("foo2-data-mod"), 0600)
	require.NoError(t, err)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt2, err = ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)
	require.NotEqual(t, string(dt), string(dt2))
}

func testEmptyWildcard(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo nomatch* /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("contents0"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "contents0", string(dt))
}

func testWorkdirUser(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
RUN adduser -D user
USER user
WORKDIR /mydir
RUN [ "$(stat -c "%U %G" /mydir)" == "user user" ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testWorkdirCopyIgnoreRelative(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch AS base
WORKDIR /foo
COPY Dockerfile / 
FROM scratch
# relative path still loaded as absolute
COPY --from=base Dockerfile .
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testWorkdirExists(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
RUN adduser -D user
RUN mkdir /mydir && chown user:user /mydir
WORKDIR /mydir
RUN [ "$(stat -c "%U %G" /mydir)" == "user user" ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testCopyChownCreateDest(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
ARG group
ENV owner user01
RUN adduser -D user
RUN adduser -D user01
COPY --chown=user:user . /dest
COPY --chown=${owner}:${group} . /dest01
RUN [ "$(stat -c "%U %G" /dest)" == "user user" ]
RUN [ "$(stat -c "%U %G" /dest01)" == "user01 user" ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
			"build-arg:group":                   "user",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testCopyThroughSymlinkContext(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY link/foo .
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.Symlink("sub", "link"),
		fstest.CreateDir("sub", 0700),
		fstest.CreateFile("sub/foo", []byte(`contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "contents", string(dt))
}

func testCopyThroughSymlinkMultiStage(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox AS build
RUN mkdir -p /out/sub && ln -s /out/sub /sub && ln -s out/sub /sub2 && echo -n "data" > /sub/foo
FROM scratch
COPY --from=build /sub/foo .
COPY --from=build /sub2/foo bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "data", string(dt))
}

func testCopySocket(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY . /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateSocket("socket.sock", 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	fi, err := os.Lstat(filepath.Join(destDir, "socket.sock"))
	require.NoError(t, err)
	// make sure socket is converted to regular file.
	require.Equal(t, fi.Mode().IsRegular(), true)
}

func testIgnoreEntrypoint(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox
ENTRYPOINT ["/nosuchcmd"]
RUN ["ls"]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testQuotedMetaArgs(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
ARG a1="box"
ARG a2="$a1-foo"
FROM busy$a1 AS build
ARG a2
ARG a3="bar-$a2"
RUN echo -n $a3 > /out
FROM scratch
COPY --from=build /out .
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Equal(t, "bar-box-foo", string(dt))
}

func testExportMultiPlatform(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
ARG TARGETARCH
ARG TARGETPLATFORM
LABEL target=$TARGETPLATFORM
COPY arch-$TARGETARCH whoami
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("arch-arm", []byte(`i am arm`), 0600),
		fstest.CreateFile("arch-amd64", []byte(`i am amd64`), 0600),
		fstest.CreateFile("arch-s390x", []byte(`i am s390x`), 0600),
		fstest.CreateFile("arch-ppc64le", []byte(`i am ppc64le`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
		FrontendAttrs: map[string]string{
			"platform": "windows/amd64,linux/arm,linux/s390x",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "windows_amd64/whoami"))
	require.NoError(t, err)
	require.Equal(t, "i am amd64", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "linux_arm_v7/whoami"))
	require.NoError(t, err)
	require.Equal(t, "i am arm", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "linux_s390x/whoami"))
	require.NoError(t, err)
	require.Equal(t, "i am s390x", string(dt))

	// repeat with oci exporter

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	out := filepath.Join(destDir, "out.tar")
	outW, err := os.Create(out)
	require.NoError(t, err)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
		FrontendAttrs: map[string]string{
			"platform": "windows/amd64,linux/arm/v6,linux/ppc64le",
		},
		Exports: []client.ExportEntry{
			{
				Type:   client.ExporterOCI,
				Output: fixedWriteCloser(outW),
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out.tar"))
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(dt, false)
	require.NoError(t, err)

	var idx ocispec.Index
	err = json.Unmarshal(m["index.json"].Data, &idx)
	require.NoError(t, err)

	mlistHex := idx.Manifests[0].Digest.Hex()

	idx = ocispec.Index{}
	err = json.Unmarshal(m["blobs/sha256/"+mlistHex].Data, &idx)
	require.NoError(t, err)

	require.Equal(t, 3, len(idx.Manifests))

	for i, exp := range []struct {
		p    string
		os   string
		arch string
		dt   string
	}{
		{p: "windows/amd64", os: "windows", arch: "amd64", dt: "i am amd64"},
		{p: "linux/arm/v6", os: "linux", arch: "arm", dt: "i am arm"},
		{p: "linux/ppc64le", os: "linux", arch: "ppc64le", dt: "i am ppc64le"},
	} {
		t.Run(exp.p, func(t *testing.T) {
			require.Equal(t, exp.p, platforms.Format(*idx.Manifests[i].Platform))

			var mfst ocispec.Manifest
			err = json.Unmarshal(m["blobs/sha256/"+idx.Manifests[i].Digest.Hex()].Data, &mfst)
			require.NoError(t, err)

			require.Equal(t, 1, len(mfst.Layers))

			m2, err := testutil.ReadTarToMap(m["blobs/sha256/"+mfst.Layers[0].Digest.Hex()].Data, true)
			require.NoError(t, err)
			require.Equal(t, exp.dt, string(m2["whoami"].Data))

			var img ocispec.Image
			err = json.Unmarshal(m["blobs/sha256/"+mfst.Config.Digest.Hex()].Data, &img)
			require.NoError(t, err)

			require.Equal(t, exp.os, img.OS)
			require.Equal(t, exp.arch, img.Architecture)
			v, ok := img.Config.Labels["target"]
			require.True(t, ok)
			require.Equal(t, exp.p, v)
		})
	}
}

// tonistiigi/fsutil#46
func testContextChangeDirToFile(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateDir("foo", 0700),
		fstest.CreateFile("foo/bar", []byte(`contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`contents2`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "contents2", string(dt))
}

func testNoSnapshotLeak(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	du, err := c.DiskUsage(context.TODO())
	require.NoError(t, err)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	du2, err := c.DiskUsage(context.TODO())
	require.NoError(t, err)

	require.Equal(t, len(du), len(du2))
}

// #1197
func testCopyFollowAllSymlinks(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo /
COPY foo/sub bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("bar", []byte(`bar-contents`), 0600),
		fstest.CreateDir("foo", 0700),
		fstest.Symlink("../bar", "foo/sub"),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testCopySymlinks(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo /
COPY sub/l* alllinks/
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("bar", []byte(`bar-contents`), 0600),
		fstest.Symlink("bar", "foo"),
		fstest.CreateDir("sub", 0700),
		fstest.CreateFile("sub/lfile", []byte(`lfile-contents`), 0600),
		fstest.Symlink("subfile", "sub/l0"),
		fstest.CreateFile("sub/subfile", []byte(`subfile-contents`), 0600),
		fstest.Symlink("second", "sub/l1"),
		fstest.Symlink("baz", "sub/second"),
		fstest.CreateFile("sub/baz", []byte(`baz-contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "bar-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "alllinks/l0"))
	require.NoError(t, err)
	require.Equal(t, "subfile-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "alllinks/lfile"))
	require.NoError(t, err)
	require.Equal(t, "lfile-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "alllinks/l1"))
	require.NoError(t, err)
	require.Equal(t, "baz-contents", string(dt))
}

func testHTTPDockerfile(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox
RUN echo -n "foo-contents" > /foo
FROM scratch
COPY --from=0 /foo /foo
`)

	srcDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	err = ioutil.WriteFile(filepath.Join(srcDir, "Dockerfile"), dockerfile, 0600)
	require.NoError(t, err)

	resp := httpserver.Response{
		Etag:    identity.NewID(),
		Content: dockerfile,
	}

	server := httpserver.NewTestServer(map[string]httpserver.Response{
		"/df": resp,
	})
	defer server.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"context":  server.URL + "/df",
			"filename": "mydockerfile", // this is bogus, any name should work
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

}

func testCmdShell(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("requires local image store")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	dockerfile := []byte(`
FROM scratch
CMD ["test"]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := "docker.io/moby/cmdoverridetest:latest"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dockerfile = []byte(`
FROM docker.io/moby/cmdoverridetest:latest
SHELL ["ls"]
ENTRYPOINT my entrypoint
`)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	target = "docker.io/moby/cmdoverridetest2:latest"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	ctr, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer ctr.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := ctr.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, ctr.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, ctr.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.Equal(t, []string(nil), ociimg.Config.Cmd)
	require.Equal(t, []string{"ls", "my entrypoint"}, ociimg.Config.Entrypoint)
}

func testPullScratch(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("requires local image store")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	dockerfile := []byte(`
FROM scratch
LABEL foo=bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := "docker.io/moby/testpullscratch:latest"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dockerfile = []byte(`
FROM docker.io/moby/testpullscratch:latest
LABEL bar=baz
COPY foo .
`)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foo-contents"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	target = "docker.io/moby/testpullscratch2:latest"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	ctr, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer ctr.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := ctr.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, ctr.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, ctr.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.Equal(t, "layers", ociimg.RootFS.Type)
	require.Equal(t, 1, len(ociimg.RootFS.DiffIDs))
	v, ok := ociimg.Config.Labels["foo"]
	require.True(t, ok)
	require.Equal(t, "bar", v)
	v, ok = ociimg.Config.Labels["bar"]
	require.True(t, ok)
	require.Equal(t, "baz", v)

	echo := llb.Image("busybox").
		Run(llb.Shlex(`sh -c "echo -n foo0 > /empty/foo"`)).
		AddMount("/empty", llb.Image("docker.io/moby/testpullscratch:latest"))

	def, err := echo.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "foo0", string(dt))
}

func testGlobalArg(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
ARG tag=nosuchtag
FROM busybox:${tag}
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:tag": "latest",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testDockerfileDirs(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)

	dockerfile := []byte(`
	FROM busybox
	COPY foo /foo2
	COPY foo /
	RUN echo -n bar > foo3
	RUN test -f foo
	RUN cmp -s foo foo2
	RUN cmp -s foo foo3
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("bar"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	cmd := sb.Cmd(args)
	require.NoError(t, cmd.Run())

	_, err = os.Stat(trace)
	require.NoError(t, err)

	// relative urls
	args, trace = f.DFCmdArgs(".", ".")
	defer os.RemoveAll(trace)

	cmd = sb.Cmd(args)
	cmd.Dir = dir
	require.NoError(t, cmd.Run())

	_, err = os.Stat(trace)
	require.NoError(t, err)

	// different context and dockerfile directories
	dir1, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir1)

	dir2, err := tmpdir(
		fstest.CreateFile("foo", []byte("bar"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir2)

	args, trace = f.DFCmdArgs(dir2, dir1)
	defer os.RemoveAll(trace)

	cmd = sb.Cmd(args)
	cmd.Dir = dir
	require.NoError(t, cmd.Run())

	_, err = os.Stat(trace)
	require.NoError(t, err)

	// TODO: test trace file output, cache hits, logs etc.
	// TODO: output metadata about original dockerfile command in trace
}

func testDockerfileInvalidCommand(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)
	dockerfile := []byte(`
	FROM busybox
	RUN invalidcmd
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	cmd := sb.Cmd(args)
	stdout := new(bytes.Buffer)
	cmd.Stderr = stdout
	err = cmd.Run()
	require.Error(t, err)
	require.Contains(t, stdout.String(), "/bin/sh -c invalidcmd")
	require.Contains(t, stdout.String(), "executor failed running")
}

func testDockerfileADDFromURL(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)

	modTime := time.Now().Add(-24 * time.Hour) // avoid falso positive with current time

	resp := httpserver.Response{
		Etag:    identity.NewID(),
		Content: []byte("content1"),
	}

	resp2 := httpserver.Response{
		Etag:         identity.NewID(),
		LastModified: &modTime,
		Content:      []byte("content2"),
	}

	server := httpserver.NewTestServer(map[string]httpserver.Response{
		"/foo": resp,
		"/":    resp2,
	})
	defer server.Close()

	dockerfile := []byte(fmt.Sprintf(`
FROM scratch
ADD %s /dest/
`, server.URL+"/foo"))

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err := tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd := sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	err = cmd.Run()
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest/foo"))
	require.NoError(t, err)
	require.Equal(t, []byte("content1"), dt)

	// test the default properties
	dockerfile = []byte(fmt.Sprintf(`
FROM scratch
ADD %s /dest/
`, server.URL+"/"))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace = f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err = tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd = sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	err = cmd.Run()
	require.NoError(t, err)

	destFile := filepath.Join(destDir, "dest/__unnamed__")
	dt, err = ioutil.ReadFile(destFile)
	require.NoError(t, err)
	require.Equal(t, []byte("content2"), dt)

	fi, err := os.Stat(destFile)
	require.NoError(t, err)
	require.Equal(t, modTime.Format(http.TimeFormat), fi.ModTime().Format(http.TimeFormat))
}

func testDockerfileAddArchive(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	expectedContent := []byte("content0")
	err := tw.WriteHeader(&tar.Header{
		Name:     "foo",
		Typeflag: tar.TypeReg,
		Size:     int64(len(expectedContent)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(expectedContent)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	dockerfile := []byte(`
FROM scratch
ADD t.tar /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("t.tar", buf.Bytes(), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err := tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd := sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, expectedContent, dt)

	// add gzip tar
	buf2 := bytes.NewBuffer(nil)
	gz := gzip.NewWriter(buf2)
	_, err = gz.Write(buf.Bytes())
	require.NoError(t, err)
	err = gz.Close()
	require.NoError(t, err)

	dockerfile = []byte(`
FROM scratch
ADD t.tar.gz /
`)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("t.tar.gz", buf2.Bytes(), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace = f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err = tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd = sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, expectedContent, dt)

	// COPY doesn't extract
	dockerfile = []byte(`
FROM scratch
COPY t.tar.gz /
`)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("t.tar.gz", buf2.Bytes(), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace = f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err = tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd = sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "t.tar.gz"))
	require.NoError(t, err)
	require.Equal(t, buf2.Bytes(), dt)

	// ADD from URL doesn't extract
	resp := httpserver.Response{
		Etag:    identity.NewID(),
		Content: buf2.Bytes(),
	}

	server := httpserver.NewTestServer(map[string]httpserver.Response{
		"/t.tar.gz": resp,
	})
	defer server.Close()

	dockerfile = []byte(fmt.Sprintf(`
FROM scratch
ADD %s /
`, server.URL+"/t.tar.gz"))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace = f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err = tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd = sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "t.tar.gz"))
	require.NoError(t, err)
	require.Equal(t, buf2.Bytes(), dt)

	// https://github.com/moby/buildkit/issues/386
	dockerfile = []byte(fmt.Sprintf(`
FROM scratch
ADD %s /newname.tar.gz
`, server.URL+"/t.tar.gz"))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace = f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err = tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd = sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "newname.tar.gz"))
	require.NoError(t, err)
	require.Equal(t, buf2.Bytes(), dt)
}

func testDockerfileAddArchiveWildcard(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	expectedContent := []byte("content0")
	err := tw.WriteHeader(&tar.Header{
		Name:     "foo",
		Typeflag: tar.TypeReg,
		Size:     int64(len(expectedContent)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(expectedContent)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	buf2 := bytes.NewBuffer(nil)
	tw = tar.NewWriter(buf2)
	expectedContent = []byte("content1")
	err = tw.WriteHeader(&tar.Header{
		Name:     "bar",
		Typeflag: tar.TypeReg,
		Size:     int64(len(expectedContent)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(expectedContent)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	dockerfile := []byte(`
FROM scratch
ADD *.tar /dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("t.tar", buf.Bytes(), 0600),
		fstest.CreateFile("b.tar", buf2.Bytes(), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest/foo"))
	require.NoError(t, err)
	require.Equal(t, "content0", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "dest/bar"))
	require.NoError(t, err)
	require.Equal(t, "content1", string(dt))
}

func testDockerfileAddChownExpand(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
ARG group
ENV owner 1000
ADD --chown=${owner}:${group} foo /
RUN [ "$(stat -c "%u %G" /foo)" == "1000 nogroup" ]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`foo-contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
			"build-arg:group":                   "nogroup",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testSymlinkDestination(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	expectedContent := []byte("content0")
	err := tw.WriteHeader(&tar.Header{
		Name:     "symlink",
		Typeflag: tar.TypeSymlink,
		Linkname: "../tmp/symlink-target",
		Mode:     0755,
	})
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	dockerfile := []byte(`
FROM scratch
ADD t.tar /
COPY foo /symlink/
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", expectedContent, 0600),
		fstest.CreateFile("t.tar", buf.Bytes(), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	destDir, err := tmpdir()
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	cmd := sb.Cmd(args + fmt.Sprintf(" --exporter=local --exporter-opt output=%s", destDir))
	require.NoError(t, cmd.Run())

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "tmp/symlink-target/foo"))
	require.NoError(t, err)
	require.Equal(t, expectedContent, dt)
}

func testDockerfileScratchConfig(t *testing.T, sb integration.Sandbox) {
	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("only for containerd worker")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)
	dockerfile := []byte(`
FROM scratch
ENV foo=bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	target := "example.com/moby/dockerfilescratch:test"
	cmd := sb.Cmd(args + " --exporter=image --exporter-opt=name=" + target)
	err = cmd.Run()
	require.NoError(t, err)

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, client.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, client.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.NotEqual(t, "", ociimg.OS)
	require.NotEqual(t, "", ociimg.Architecture)
	require.NotEqual(t, "", ociimg.Config.WorkingDir)
	require.Equal(t, "layers", ociimg.RootFS.Type)
	require.Equal(t, 0, len(ociimg.RootFS.DiffIDs))

	require.Equal(t, 1, len(ociimg.History))
	require.Contains(t, ociimg.History[0].CreatedBy, "ENV foo=bar")
	require.Equal(t, true, ociimg.History[0].EmptyLayer)

	require.Contains(t, ociimg.Config.Env, "foo=bar")
	require.Condition(t, func() bool {
		for _, env := range ociimg.Config.Env {
			if strings.HasPrefix(env, "PATH=") {
				return true
			}
		}
		return false
	})
}

func testExposeExpansion(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)

	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
ARG PORTS="3000 4000/udp"
EXPOSE $PORTS
EXPOSE 5000
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := "example.com/moby/dockerfileexpansion:test"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		return
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, client.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, client.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.Equal(t, 3, len(ociimg.Config.ExposedPorts))

	var ports []string
	for p := range ociimg.Config.ExposedPorts {
		ports = append(ports, p)
	}

	sort.Strings(ports)

	require.Equal(t, "3000/tcp", ports[0])
	require.Equal(t, "4000/udp", ports[1])
	require.Equal(t, "5000/tcp", ports[2])
}

func testDockerignore(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY . .
`)

	dockerignore := []byte(`
ba*
Dockerfile
!bay
.dockerignore
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`foo-contents`), 0600),
		fstest.CreateFile("bar", []byte(`bar-contents`), 0600),
		fstest.CreateFile("baz", []byte(`baz-contents`), 0600),
		fstest.CreateFile("bay", []byte(`bay-contents`), 0600),
		fstest.CreateFile(".dockerignore", dockerignore, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	_, err = os.Stat(filepath.Join(destDir, ".dockerignore"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))

	_, err = os.Stat(filepath.Join(destDir, "Dockerfile"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))

	_, err = os.Stat(filepath.Join(destDir, "bar"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))

	_, err = os.Stat(filepath.Join(destDir, "baz"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "bay"))
	require.NoError(t, err)
	require.Equal(t, "bay-contents", string(dt))
}

func testDockerignoreInvalid(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY . .
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile(".dockerignore", []byte("!\n"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(ctx, c, client.SolveOpt{
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	// err is either the expected error due to invalid dockerignore or error from the timeout
	require.Error(t, err)
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	default:
	}
}

func testExportedHistory(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)
	f.RequiresBuildctl(t)

	// using multi-stage to test that history is scoped to one stage
	dockerfile := []byte(`
FROM busybox AS base
ENV foo=bar
COPY foo /foo2
FROM busybox
LABEL lbl=val
COPY --from=base foo2 foo3
WORKDIR /
RUN echo bar > foo4
RUN ["ls"]
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("contents0"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	args, trace := f.DFCmdArgs(dir, dir)
	defer os.RemoveAll(trace)

	target := "example.com/moby/dockerfilescratch:test"
	cmd := sb.Cmd(args + " --exporter=image --exporter-opt=name=" + target)
	require.NoError(t, cmd.Run())

	// TODO: expose this test to OCI worker

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("only for containerd worker")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, client.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, client.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.Equal(t, "layers", ociimg.RootFS.Type)
	// this depends on busybox. should be ok after freezing images
	require.Equal(t, 3, len(ociimg.RootFS.DiffIDs))

	require.Equal(t, 7, len(ociimg.History))
	require.Contains(t, ociimg.History[2].CreatedBy, "lbl=val")
	require.Equal(t, true, ociimg.History[2].EmptyLayer)
	require.NotNil(t, ociimg.History[2].Created)
	require.Contains(t, ociimg.History[3].CreatedBy, "COPY foo2 foo3")
	require.Equal(t, false, ociimg.History[3].EmptyLayer)
	require.NotNil(t, ociimg.History[3].Created)
	require.Contains(t, ociimg.History[4].CreatedBy, "WORKDIR /")
	require.Equal(t, true, ociimg.History[4].EmptyLayer)
	require.NotNil(t, ociimg.History[4].Created)
	require.Contains(t, ociimg.History[5].CreatedBy, "echo bar > foo4")
	require.Equal(t, false, ociimg.History[5].EmptyLayer)
	require.NotNil(t, ociimg.History[5].Created)
	require.Contains(t, ociimg.History[6].CreatedBy, "RUN ls")
	require.Equal(t, true, ociimg.History[6].EmptyLayer)
	require.NotNil(t, ociimg.History[6].Created)
}

func skipDockerd(t *testing.T, sb integration.Sandbox) {
	// TODO: remove me once dockerd supports the image and exporter.
	t.Helper()
	if os.Getenv("TEST_DOCKERD") == "1" {
		t.Skip("dockerd missing a required exporter, cache exporter, or entitlement")
	}
}

func testUser(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)

	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS base
RUN mkdir -m 0777 /out
RUN id -un > /out/rootuser

# Make sure our defaults work
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)" = '0:0/root:root' ]

# TODO decide if "args.user = strconv.Itoa(syscall.Getuid())" is acceptable behavior for changeUser in sysvinit instead of "return nil" when "USER" isn't specified (so that we get the proper group list even if that is the empty list, even in the default case of not supplying an explicit USER to run as, which implies USER 0)
USER root
RUN [ "$(id -G):$(id -Gn)" = '0 10:root wheel' ]

# Setup dockerio user and group
RUN echo 'dockerio:x:1001:1001::/bin:/bin/false' >> /etc/passwd && \
	echo 'dockerio:x:1001:' >> /etc/group

# Make sure we can switch to our user and all the information is exactly as we expect it to be
USER dockerio
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001:dockerio' ]

# Switch back to root and double check that worked exactly as we might expect it to
USER root
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '0:0/root:root/0 10:root wheel' ] && \
        # Add a "supplementary" group for our dockerio user
	echo 'supplementary:x:1002:dockerio' >> /etc/group

# ... and then go verify that we get it like we expect
USER dockerio
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001 1002:dockerio supplementary' ]
USER 1001
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001 1002:dockerio supplementary' ]

# super test the new "user:group" syntax
USER dockerio:dockerio
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001:dockerio' ]
USER 1001:dockerio
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001:dockerio' ]
USER dockerio:1001
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001:dockerio' ]
USER 1001:1001
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1001/dockerio:dockerio/1001:dockerio' ]
USER dockerio:supplementary
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1002/dockerio:supplementary/1002:supplementary' ]
USER dockerio:1002
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1002/dockerio:supplementary/1002:supplementary' ]
USER 1001:supplementary
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1002/dockerio:supplementary/1002:supplementary' ]
USER 1001:1002
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1001:1002/dockerio:supplementary/1002:supplementary' ]

# make sure unknown uid/gid still works properly
USER 1042:1043
RUN [ "$(id -u):$(id -g)/$(id -un):$(id -gn)/$(id -G):$(id -Gn)" = '1042:1043/1042:1043/1043:1043' ]
USER daemon
RUN id -un > /out/daemonuser
FROM scratch
COPY --from=base /out /
USER nobody
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "rootuser"))
	require.NoError(t, err)
	require.Equal(t, "root\n", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "daemonuser"))
	require.NoError(t, err)
	require.Equal(t, "daemon\n", string(dt))

	// test user in exported
	target := "example.com/moby/dockerfileuser:test"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		return
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, client.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err = content.ReadBlob(ctx, client.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.Equal(t, "nobody", ociimg.Config.User)
}

func testCopyChown(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox AS base
ENV owner 1000
RUN mkdir -m 0777 /out
COPY --chown=daemon foo /
COPY --chown=1000:nogroup bar /baz
ARG group
COPY --chown=${owner}:${group} foo /foobis
RUN stat -c "%U %G" /foo  > /out/fooowner
RUN stat -c "%u %G" /baz/sub  > /out/subowner
RUN stat -c "%u %G" /foobis  > /out/foobisowner
FROM scratch
COPY --from=base /out /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`foo-contents`), 0600),
		fstest.CreateDir("bar", 0700),
		fstest.CreateFile("bar/sub", nil, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
			"build-arg:group":                   "nogroup",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "fooowner"))
	require.NoError(t, err)
	require.Equal(t, "daemon daemon\n", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subowner"))
	require.NoError(t, err)
	require.Equal(t, "1000 nogroup\n", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "foobisowner"))
	require.NoError(t, err)
	require.Equal(t, "1000 nogroup\n", string(dt))
}

func testCopyOverrideFiles(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch AS base
COPY sub sub
COPY sub sub
COPY files/foo.go dest/foo.go
COPY files/foo.go dest/foo.go
COPY files dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateDir("sub", 0700),
		fstest.CreateDir("sub/dir1", 0700),
		fstest.CreateDir("sub/dir1/dir2", 0700),
		fstest.CreateFile("sub/dir1/dir2/foo", []byte(`foo-contents`), 0600),
		fstest.CreateDir("files", 0700),
		fstest.CreateFile("files/foo.go", []byte(`foo.go-contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "sub/dir1/dir2/foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "dest/foo.go"))
	require.NoError(t, err)
	require.Equal(t, "foo.go-contents", string(dt))
}

func testCopyVarSubstitution(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch AS base
ENV FOO bar
COPY $FOO baz
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("bar", []byte(`bar-contents`), 0600),
	)

	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "baz"))
	require.NoError(t, err)
	require.Equal(t, "bar-contents", string(dt))
}

func testCopyWildcards(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch AS base
COPY *.go /gofiles/
COPY f*.go foo2.go
COPY sub/* /subdest/
COPY sub/*/dir2/foo /subdest2/
COPY sub/*/dir2/foo /subdest3/bar
COPY . all/
COPY sub/dir1/ subdest4
COPY sub/dir1/. subdest5
COPY sub/dir1 subdest6
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo.go", []byte(`foo-contents`), 0600),
		fstest.CreateFile("bar.go", []byte(`bar-contents`), 0600),
		fstest.CreateDir("sub", 0700),
		fstest.CreateDir("sub/dir1", 0700),
		fstest.CreateDir("sub/dir1/dir2", 0700),
		fstest.CreateFile("sub/dir1/dir2/foo", []byte(`foo-contents`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "gofiles/foo.go"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "gofiles/bar.go"))
	require.NoError(t, err)
	require.Equal(t, "bar-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "foo2.go"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	if isFileOp { // non-fileop implementation is historically buggy
		dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest/dir2/foo"))
		require.NoError(t, err)
		require.Equal(t, "foo-contents", string(dt))
	}

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest2/foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest3/bar"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "all/foo.go"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest4/dir2/foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest5/dir2/foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "subdest6/dir2/foo"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))
}

func testCopyRelative(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM busybox
WORKDIR /test1
WORKDIR test2
RUN sh -c "[ "$PWD" = '/test1/test2' ]"
COPY foo ./
RUN sh -c "[ $(cat /test1/test2/foo) = 'hello' ]"
ADD foo ./bar/baz
RUN sh -c "[ $(cat /test1/test2/bar/baz) = 'hello' ]"
COPY foo ./bar/baz2
RUN sh -c "[ $(cat /test1/test2/bar/baz2) = 'hello' ]"
WORKDIR ..
COPY foo ./
RUN sh -c "[ $(cat /test1/foo) = 'hello' ]"
COPY foo /test3/
RUN sh -c "[ $(cat /test3/foo) = 'hello' ]"
WORKDIR /test4
COPY . .
RUN sh -c "[ $(cat /test4/foo) = 'hello' ]"
WORKDIR /test5/test6
COPY foo ../
RUN sh -c "[ $(cat /test5/foo) = 'hello' ]"
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte(`hello`), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testDockerfileFromGit(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	gitDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(gitDir)

	dockerfile := `
FROM busybox AS build
RUN echo -n fromgit > foo
FROM scratch
COPY --from=build foo bar
`

	err = ioutil.WriteFile(filepath.Join(gitDir, "Dockerfile"), []byte(dockerfile), 0600)
	require.NoError(t, err)

	err = runShell(gitDir,
		"git init",
		"git config --local user.email test",
		"git config --local user.name test",
		"git add Dockerfile",
		"git commit -m initial",
		"git branch first",
	)
	require.NoError(t, err)

	dockerfile += `
COPY --from=build foo bar2
`

	err = ioutil.WriteFile(filepath.Join(gitDir, "Dockerfile"), []byte(dockerfile), 0600)
	require.NoError(t, err)

	err = runShell(gitDir,
		"git add Dockerfile",
		"git commit -m second",
		"git update-server-info",
	)
	require.NoError(t, err)

	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(gitDir))))
	defer server.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"context": server.URL + "/.git#first",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, "fromgit", string(dt))

	_, err = os.Stat(filepath.Join(destDir, "bar2"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))

	// second request from master branch contains both files
	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"context": server.URL + "/.git",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, "fromgit", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "bar2"))
	require.NoError(t, err)
	require.Equal(t, "fromgit", string(dt))
}

func testDockerfileFromHTTP(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	buf := bytes.NewBuffer(nil)
	w := tar.NewWriter(buf)

	writeFile := func(fn, dt string) {
		err := w.WriteHeader(&tar.Header{
			Name:     fn,
			Mode:     0600,
			Size:     int64(len(dt)),
			Typeflag: tar.TypeReg,
		})
		require.NoError(t, err)
		_, err = w.Write([]byte(dt))
		require.NoError(t, err)
	}

	writeFile("mydockerfile", `FROM scratch
COPY foo bar
`)

	writeFile("foo", "foo-contents")

	require.NoError(t, w.Flush())

	resp := httpserver.Response{
		Etag:    identity.NewID(),
		Content: buf.Bytes(),
	}

	server := httpserver.NewTestServer(map[string]httpserver.Response{
		"/myurl": resp,
	})
	defer server.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"context":  server.URL + "/myurl",
			"filename": "mydockerfile",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, "foo-contents", string(dt))
}

func testMultiStageImplicitFrom(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY --from=busybox /etc/passwd test
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "test"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "root")

	// testing masked image will load actual stage

	dockerfile = []byte(`
FROM busybox AS golang
RUN mkdir /usr/bin && echo -n foo > /usr/bin/go

FROM scratch
COPY --from=golang /usr/bin/go go
`)

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "go"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "foo")
}

func testMultiStageCaseInsensitive(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch AS STAge0
COPY foo bar
FROM scratch AS staGE1
COPY --from=staGE0 bar baz
FROM scratch
COPY --from=stage1 baz bax
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foo-contents"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
		FrontendAttrs: map[string]string{
			"target": "Stage1",
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "baz"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "foo-contents")
}

func testLabels(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM scratch
LABEL foo=bar
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	target := "example.com/moby/dockerfilelabels:test"
	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"label:bar": "baz",
		},
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("only for containerd worker")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx, client.ContentStore(), platforms.Default())
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, client.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	v, ok := ociimg.Config.Labels["foo"]
	require.True(t, ok)
	require.Equal(t, "bar", v)

	v, ok = ociimg.Config.Labels["bar"]
	require.True(t, ok)
	require.Equal(t, "baz", v)
}

func testOnBuildCleared(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	dockerfile := []byte(`
FROM busybox
ONBUILD RUN mkdir -p /out && echo -n 11 >> /out/foo
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := registry + "/buildkit/testonbuild:base"

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"push": "true",
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dockerfile = []byte(fmt.Sprintf(`
	FROM %s 
	`, target))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	target2 := registry + "/buildkit/testonbuild:child"

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"push": "true",
					"name": target2,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dockerfile = []byte(fmt.Sprintf(`
	FROM %s AS base
	FROM scratch
	COPY --from=base /out /
	`, target2))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, "11", string(dt))
}

func testCacheMultiPlatformImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	dockerfile := []byte(`
FROM --platform=$BUILDPLATFORM busybox AS base
ARG TARGETARCH
RUN echo -n $TARGETARCH> arch && cat /dev/urandom | head -c 100 | sha256sum > unique
FROM scratch
COPY --from=base unique /
COPY --from=base arch /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := registry + "/buildkit/testexportdf:multi"

	// exportCache := []client.CacheOptionsEntry{
	// 	{
	// 		Type:  "registry",
	// 		Attrs: map[string]string{"ref": target},
	// 	},
	// }
	// importCache := target

	exportCache := []client.CacheOptionsEntry{
		{
			Type: "inline",
		},
	}
	importCache := target + "-img"

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"push": "true",
					"name": target + "-img",
				},
			},
		},
		CacheExports: exportCache,
		FrontendAttrs: map[string]string{
			"platform": "linux/amd64,linux/arm/v7",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	desc, provider, err := contentutil.ProviderFromRef(target + "-img")
	require.NoError(t, err)

	imgMap, err := readIndex(provider, desc)
	require.NoError(t, err)

	require.Equal(t, 2, len(imgMap))

	require.Equal(t, "amd64", string(imgMap["linux/amd64"].layers[1]["arch"].Data))
	dtamd := imgMap["linux/amd64"].layers[0]["unique"].Data
	dtarm := imgMap["linux/arm/v7"].layers[0]["unique"].Data
	require.NotEqual(t, dtamd, dtarm)

	for i := 0; i < 2; i++ {
		err = c.Prune(context.TODO(), nil, client.PruneAll)
		require.NoError(t, err)

		checkAllRemoved(t, c, sb)

		_, err = f.Solve(context.TODO(), c, client.SolveOpt{
			FrontendAttrs: map[string]string{
				"cache-from": importCache,
				"platform":   "linux/amd64,linux/arm/v7",
			},
			Exports: []client.ExportEntry{
				{
					Type: client.ExporterImage,
					Attrs: map[string]string{
						"push": "true",
						"name": target + "-img",
					},
				},
			},
			CacheExports: exportCache,
			LocalDirs: map[string]string{
				builder.DefaultLocalNameDockerfile: dir,
				builder.DefaultLocalNameContext:    dir,
			},
		}, nil)
		require.NoError(t, err)

		desc2, provider, err := contentutil.ProviderFromRef(target + "-img")
		require.NoError(t, err)

		require.Equal(t, desc.Digest, desc2.Digest)

		imgMap, err = readIndex(provider, desc2)
		require.NoError(t, err)

		require.Equal(t, 2, len(imgMap))

		require.Equal(t, "arm", string(imgMap["linux/arm/v7"].layers[1]["arch"].Data))
		dtamd2 := imgMap["linux/amd64"].layers[0]["unique"].Data
		dtarm2 := imgMap["linux/arm/v7"].layers[0]["unique"].Data
		require.Equal(t, string(dtamd), string(dtamd2))
		require.Equal(t, string(dtarm), string(dtarm2))
	}
}

func testCacheImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	dockerfile := []byte(`
FROM busybox AS base
COPY foo const
#RUN echo -n foobar > const
RUN cat /dev/urandom | head -c 100 | sha256sum > unique
FROM scratch
COPY --from=base const /
COPY --from=base unique /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foobar"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	target := registry + "/buildkit/testexportdf:latest"

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		CacheExports: []client.CacheOptionsEntry{
			{
				Type:  "registry",
				Attrs: map[string]string{"ref": target},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "const"))
	require.NoError(t, err)
	require.Equal(t, "foobar", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)

	err = c.Prune(context.TODO(), nil, client.PruneAll)
	require.NoError(t, err)

	checkAllRemoved(t, c, sb)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"cache-from": target,
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, nil)
	require.NoError(t, err)

	dt2, err := ioutil.ReadFile(filepath.Join(destDir, "const"))
	require.NoError(t, err)
	require.Equal(t, "foobar", string(dt2))

	dt2, err = ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)
	require.Equal(t, string(dt), string(dt2))

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)
}

func testReproducibleIDs(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox
ENV foo=bar
COPY foo /
RUN echo bar > bar
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foo-contents"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	target := "example.com/moby/dockerfileids:test"
	opt := client.SolveOpt{
		FrontendAttrs: map[string]string{},
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	target2 := "example.com/moby/dockerfileids2:test"
	opt.Exports[0].Attrs["name"] = target2

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("only for containerd worker")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	img, err := client.ImageService().Get(ctx, target)
	require.NoError(t, err)
	img2, err := client.ImageService().Get(ctx, target2)
	require.NoError(t, err)

	require.Equal(t, img.Target, img2.Target)
}

func testImportExportReproducibleIDs(t *testing.T, sb integration.Sandbox) {
	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		t.Skip("only for containerd worker")
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	f := getFrontend(t, sb)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	dockerfile := []byte(`
FROM busybox
ENV foo=bar
COPY foo /
RUN echo bar > bar
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("foobar"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	target := "example.com/moby/dockerfileexpids:test"
	cacheTarget := registry + "/test/dockerfileexpids:cache"
	opt := client.SolveOpt{
		FrontendAttrs: map[string]string{},
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": target,
				},
			},
		},
		CacheExports: []client.CacheOptionsEntry{
			{
				Type:  "registry",
				Attrs: map[string]string{"ref": cacheTarget},
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	ctd, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer ctd.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	img, err := ctd.ImageService().Get(ctx, target)
	require.NoError(t, err)

	err = ctd.ImageService().Delete(ctx, target)
	require.NoError(t, err)

	err = c.Prune(context.TODO(), nil, client.PruneAll)
	require.NoError(t, err)

	checkAllRemoved(t, c, sb)

	target2 := "example.com/moby/dockerfileexpids2:test"

	opt.Exports[0].Attrs["name"] = target2
	opt.FrontendAttrs["cache-from"] = cacheTarget

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	img2, err := ctd.ImageService().Get(ctx, target2)
	require.NoError(t, err)

	require.Equal(t, img.Target, img2.Target)
}

func testNoCache(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS s0
RUN cat /dev/urandom | head -c 100 | sha256sum | tee unique
FROM busybox AS s1
RUN cat /dev/urandom | head -c 100 | sha256sum | tee unique2
FROM scratch
COPY --from=s0 unique /
COPY --from=s1 unique2 /
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt := client.SolveOpt{
		FrontendAttrs: map[string]string{},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	destDir2, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt.FrontendAttrs["no-cache"] = ""
	opt.Exports[0].OutputDir = destDir2

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	unique1Dir1, err := ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)

	unique1Dir2, err := ioutil.ReadFile(filepath.Join(destDir2, "unique"))
	require.NoError(t, err)

	unique2Dir1, err := ioutil.ReadFile(filepath.Join(destDir, "unique2"))
	require.NoError(t, err)

	unique2Dir2, err := ioutil.ReadFile(filepath.Join(destDir2, "unique2"))
	require.NoError(t, err)

	require.NotEqual(t, string(unique1Dir1), string(unique1Dir2))
	require.NotEqual(t, string(unique2Dir1), string(unique2Dir2))

	destDir3, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt.FrontendAttrs["no-cache"] = "s1"
	opt.Exports[0].OutputDir = destDir3

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	unique1Dir3, err := ioutil.ReadFile(filepath.Join(destDir3, "unique"))
	require.NoError(t, err)

	unique2Dir3, err := ioutil.ReadFile(filepath.Join(destDir3, "unique2"))
	require.NoError(t, err)

	require.Equal(t, string(unique1Dir2), string(unique1Dir3))
	require.NotEqual(t, string(unique2Dir1), string(unique2Dir3))
}

func testPlatformArgsImplicit(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(fmt.Sprintf(`
FROM scratch AS build-%s
COPY foo bar
FROM build-${TARGETOS}
COPY foo2 bar2
`, runtime.GOOS))

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("d0"), 0600),
		fstest.CreateFile("foo2", []byte("d1"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt := client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, "d0", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "bar2"))
	require.NoError(t, err)
	require.Equal(t, "d1", string(dt))
}

func testPlatformArgsExplicit(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM --platform=$BUILDPLATFORM busybox AS build
ARG TARGETPLATFORM
ARG TARGETOS
RUN mkdir /out && echo -n $TARGETPLATFORM > /out/platform && echo -n $TARGETOS > /out/os
FROM scratch
COPY --from=build out .
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt := client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		FrontendAttrs: map[string]string{
			"platform":           "darwin/ppc64le",
			"build-arg:TARGETOS": "freebsd",
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "platform"))
	require.NoError(t, err)
	require.Equal(t, "darwin/ppc64le", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "os"))
	require.NoError(t, err)
	require.Equal(t, "freebsd", string(dt))
}

func testBuiltinArgs(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build
ARG FOO
ARG BAR
ARG BAZ=bazcontent
RUN echo -n $HTTP_PROXY::$NO_PROXY::$FOO::$BAR::$BAZ > /out
FROM scratch
COPY --from=build /out /

`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt := client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:FOO":        "foocontents",
			"build-arg:http_proxy": "hpvalue",
			"build-arg:NO_PROXY":   "npvalue",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Equal(t, "hpvalue::npvalue::foocontents::::bazcontent", string(dt))

	// repeat with changed default args should match the old cache
	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt = client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:FOO":        "foocontents",
			"build-arg:http_proxy": "hpvalue2",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Equal(t, "hpvalue::npvalue::foocontents::::bazcontent", string(dt))

	// changing actual value invalidates cache
	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	opt = client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:FOO":        "foocontents2",
			"build-arg:http_proxy": "hpvalue2",
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}

	_, err = f.Solve(context.TODO(), c, opt, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Equal(t, "hpvalue2::::foocontents2::::bazcontent", string(dt))
}

func testTarContext(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	dockerfile := []byte(`
FROM scratch
COPY foo /
`)

	foo := []byte("contents")

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	err := tw.WriteHeader(&tar.Header{
		Name:     "Dockerfile",
		Typeflag: tar.TypeReg,
		Size:     int64(len(dockerfile)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(dockerfile)
	require.NoError(t, err)
	err = tw.WriteHeader(&tar.Header{
		Name:     "foo",
		Typeflag: tar.TypeReg,
		Size:     int64(len(foo)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(foo)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	up := uploadprovider.New()
	url := up.Add(buf)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
			"context":                           url,
		},
		Session: []session.Attachable{up},
	}, nil)
	require.NoError(t, err)
}

func testTarContextExternalDockerfile(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)
	isFileOp := getFileOp(t, sb)

	foo := []byte("contents")

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	err := tw.WriteHeader(&tar.Header{
		Name:     "sub/dir/foo",
		Typeflag: tar.TypeReg,
		Size:     int64(len(foo)),
		Mode:     0644,
	})
	require.NoError(t, err)
	_, err = tw.Write(foo)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	dockerfile := []byte(`
FROM scratch
COPY foo bar
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	up := uploadprovider.New()
	url := up.Add(buf)

	// repeat with changed default args should match the old cache
	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		FrontendAttrs: map[string]string{
			"build-arg:BUILDKIT_DISABLE_FILEOP": strconv.FormatBool(!isFileOp),
			"context":                           url,
			"dockerfilekey":                     builder.DefaultLocalNameDockerfile,
			"contextsubdir":                     "sub/dir",
		},
		Session: []session.Attachable{up},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
		},
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "contents")
}

func testFrontendUseForwardedSolveResults(t *testing.T, sb integration.Sandbox) {
	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	dockerfile := []byte(`
FROM scratch
COPY foo foo2
`)
	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
		fstest.CreateFile("foo", []byte("data"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
		res, err := c.Solve(ctx, gateway.SolveRequest{
			Frontend: "dockerfile.v0",
		})
		if err != nil {
			return nil, err
		}

		ref, err := res.SingleRef()
		if err != nil {
			return nil, err
		}

		st2, err := ref.ToState()
		if err != nil {
			return nil, err
		}

		st := llb.Scratch().File(
			llb.Copy(st2, "foo2", "foo3"),
		)

		def, err := st.Marshal(context.TODO())
		if err != nil {
			return nil, err
		}

		return c.Solve(ctx, gateway.SolveRequest{
			Definition: def.ToPB(),
		})
	}

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Build(context.TODO(), client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
			builder.DefaultLocalNameContext:    dir,
		},
	}, "", frontend, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo3"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("data"))
}

func testFrontendInputs(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	outMount := llb.Image("busybox").Run(
		llb.Shlex(`sh -c "cat /dev/urandom | head -c 100 | sha256sum > /out/foo"`),
	).AddMount("/out", llb.Scratch())

	def, err := outMount.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	expected, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)

	dockerfile := []byte(`
FROM scratch
COPY foo foo2
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	_, err = f.Solve(context.TODO(), c, client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			builder.DefaultLocalNameDockerfile: dir,
		},
		FrontendInputs: map[string]llb.State{
			builder.DefaultLocalNameContext: outMount,
		},
	}, nil)
	require.NoError(t, err)

	actual, err := ioutil.ReadFile(filepath.Join(destDir, "foo2"))
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func testNestedDockerfileBuild(t *testing.T, sb integration.Sandbox) {
	gw := os.Getenv("FRONTEND_GATEWAY_ONLY")
	if gw == "" {
		t.Skip()
	}

	c, err := client.New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	dockerfile := []byte(`
FROM scratch
COPY foo foo2
`)
	frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
		st := llb.Dockerfile(
			llb.WithFrontendInput(builder.DefaultLocalNameContext, llb.Scratch().File(
				llb.Mkfile("foo", 0600, []byte("data")),
			)),
			llb.WithFrontendInput(builder.DefaultLocalNameDockerfile, llb.Scratch().File(
				llb.Mkfile("Dockerfile", 0600, dockerfile),
			)),
		)
		def, err := st.Marshal(ctx)
		if err != nil {
			return nil, err
		}

		res, err := c.Solve(ctx, gateway.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, err
		}

		ref, err := res.SingleRef()
		if err != nil {
			return nil, err
		}

		st2, err := ref.ToState()
		if err != nil {
			return nil, err
		}

		st3 := llb.Scratch().File(
			llb.Copy(st2, "foo2", "foo3"),
		)

		finalDef, err := st3.Marshal(ctx)
		if err != nil {
			return nil, err
		}

		return c.Solve(ctx, gateway.SolveRequest{
			Definition: finalDef.ToPB(),
		})
	}

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)

	_, err = c.Build(context.TODO(), client.SolveOpt{
		Exports: []client.ExportEntry{
			{
				Type:      client.ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, "", frontend, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo3"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("data"))
}
func tmpdir(appliers ...fstest.Applier) (string, error) {
	tmpdir, err := ioutil.TempDir("", "buildkit-dockerfile")
	if err != nil {
		return "", err
	}
	if err := fstest.Apply(appliers...).Apply(tmpdir); err != nil {
		return "", err
	}
	return tmpdir, nil
}

func runShell(dir string, cmds ...string) error {
	for _, args := range cmds {
		cmd := exec.Command("sh", "-c", args)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			return errors.Wrapf(err, "error running %v", args)
		}
	}
	return nil
}

func checkAllRemoved(t *testing.T, c *client.Client, sb integration.Sandbox) {
	retries := 0
	for {
		require.True(t, 20 > retries)
		retries++
		du, err := c.DiskUsage(context.TODO())
		require.NoError(t, err)
		if len(du) > 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		break
	}
}

func checkAllReleasable(t *testing.T, c *client.Client, sb integration.Sandbox, checkContent bool) {
	retries := 0
loop0:
	for {
		require.True(t, 20 > retries)
		retries++
		du, err := c.DiskUsage(context.TODO())
		require.NoError(t, err)
		for _, d := range du {
			if d.InUse {
				time.Sleep(500 * time.Millisecond)
				continue loop0
			}
		}
		break
	}

	err := c.Prune(context.TODO(), nil, client.PruneAll)
	require.NoError(t, err)

	du, err := c.DiskUsage(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 0, len(du))

	// examine contents of exported tars (requires containerd)
	var cdAddress string
	if cd, ok := sb.(interface {
		ContainerdAddress() string
	}); !ok {
		return
	} else {
		cdAddress = cd.ContainerdAddress()
	}

	// TODO: make public pull helper function so this can be checked for standalone as well

	client, err := newContainerd(cdAddress)
	require.NoError(t, err)
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "buildkit")
	snapshotService := client.SnapshotService("overlayfs")

	retries = 0
	for {
		count := 0
		err = snapshotService.Walk(ctx, func(context.Context, snapshots.Info) error {
			count++
			return nil
		})
		require.NoError(t, err)
		if count == 0 {
			break
		}
		require.True(t, 20 > retries)
		retries++
		time.Sleep(500 * time.Millisecond)
	}

	if !checkContent {
		return
	}

	retries = 0
	for {
		count := 0
		err = client.ContentStore().Walk(ctx, func(content.Info) error {
			count++
			return nil
		})
		require.NoError(t, err)
		if count == 0 {
			break
		}
		require.True(t, 20 > retries)
		retries++
		time.Sleep(500 * time.Millisecond)
	}
}

func newContainerd(cdAddress string) (*containerd.Client, error) {
	return containerd.New(cdAddress, containerd.WithTimeout(60*time.Second), containerd.WithDefaultRuntime("io.containerd.runtime.v1.linux"))
}

func dfCmdArgs(ctx, dockerfile, args string) (string, string) {
	traceFile := filepath.Join(os.TempDir(), "trace"+identity.NewID())
	return fmt.Sprintf("build --progress=plain %s --local context=%s --local dockerfile=%s --trace=%s", args, ctx, dockerfile, traceFile), traceFile
}

type builtinFrontend struct{}

var _ frontend = &builtinFrontend{}

func (f *builtinFrontend) Solve(ctx context.Context, c *client.Client, opt client.SolveOpt, statusChan chan *client.SolveStatus) (*client.SolveResponse, error) {
	opt.Frontend = "dockerfile.v0"
	return c.Solve(ctx, nil, opt, statusChan)
}

func (f *builtinFrontend) DFCmdArgs(ctx, dockerfile string) (string, string) {
	return dfCmdArgs(ctx, dockerfile, "--frontend dockerfile.v0")
}

func (f *builtinFrontend) RequiresBuildctl(t *testing.T) {}

type clientFrontend struct{}

var _ frontend = &clientFrontend{}

func (f *clientFrontend) Solve(ctx context.Context, c *client.Client, opt client.SolveOpt, statusChan chan *client.SolveStatus) (*client.SolveResponse, error) {
	return c.Build(ctx, opt, "", builder.Build, statusChan)
}

func (f *clientFrontend) DFCmdArgs(ctx, dockerfile string) (string, string) {
	return "", ""
}
func (f *clientFrontend) RequiresBuildctl(t *testing.T) {
	t.Skip()
}

type gatewayFrontend struct {
	gw string
}

var _ frontend = &gatewayFrontend{}

func (f *gatewayFrontend) Solve(ctx context.Context, c *client.Client, opt client.SolveOpt, statusChan chan *client.SolveStatus) (*client.SolveResponse, error) {
	opt.Frontend = "gateway.v0"
	if opt.FrontendAttrs == nil {
		opt.FrontendAttrs = make(map[string]string)
	}
	opt.FrontendAttrs["source"] = f.gw
	return c.Solve(ctx, nil, opt, statusChan)
}

func (f *gatewayFrontend) DFCmdArgs(ctx, dockerfile string) (string, string) {
	return dfCmdArgs(ctx, dockerfile, "--frontend gateway.v0 --opt=source="+f.gw)
}

func (f *gatewayFrontend) RequiresBuildctl(t *testing.T) {}

func getFrontend(t *testing.T, sb integration.Sandbox) frontend {
	v := sb.Value("frontend")
	require.NotNil(t, v)
	fn, ok := v.(frontend)
	require.True(t, ok)
	return fn
}

func getFileOp(t *testing.T, sb integration.Sandbox) bool {
	v := sb.Value("fileop")
	require.NotNil(t, v)
	vv, ok := v.(bool)
	require.True(t, ok)
	return vv
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

type secModeSandbox struct{}

func (*secModeSandbox) UpdateConfigFile(in string) string {
	return in
}

type secModeInsecure struct{}

func (*secModeInsecure) UpdateConfigFile(in string) string {
	return in + "\n\ninsecure-entitlements = [\"security.insecure\"]\n"
}

var securityInsecureGranted integration.ConfigUpdater = &secModeInsecure{}
var securityInsecureDenied integration.ConfigUpdater = &secModeSandbox{}

type networkModeHost struct{}

func (*networkModeHost) UpdateConfigFile(in string) string {
	return in + "\n\ninsecure-entitlements = [\"network.host\"]\n"
}

type networkModeSandbox struct{}

func (*networkModeSandbox) UpdateConfigFile(in string) string {
	return in
}

var networkHostGranted integration.ConfigUpdater = &networkModeHost{}
var networkHostDenied integration.ConfigUpdater = &networkModeSandbox{}

func fixedWriteCloser(wc io.WriteCloser) func(map[string]string) (io.WriteCloser, error) {
	return func(map[string]string) (io.WriteCloser, error) {
		return wc, nil
	}
}

type imageInfo struct {
	desc   ocispec.Descriptor
	layers []map[string]*testutil.TarItem
}

func readIndex(p content.Provider, desc ocispec.Descriptor) (map[string]*imageInfo, error) {
	ctx := context.TODO()
	dt, err := content.ReadBlob(ctx, p, desc)
	if err != nil {
		return nil, err
	}
	var idx ocispec.Index
	if err := json.Unmarshal(dt, &idx); err != nil {
		return nil, err
	}

	mi := map[string]*imageInfo{}

	for _, m := range idx.Manifests {
		img, err := readImage(p, m)
		if err != nil {
			return nil, err
		}
		mi[platforms.Format(*m.Platform)] = img
	}
	return mi, nil
}
func readImage(p content.Provider, desc ocispec.Descriptor) (*imageInfo, error) {
	ii := &imageInfo{desc: desc}

	ctx := context.TODO()
	dt, err := content.ReadBlob(ctx, p, desc)
	if err != nil {
		return nil, err
	}

	var mfst ocispec.Manifest
	if err := json.Unmarshal(dt, &mfst); err != nil {
		return nil, err
	}

	for _, l := range mfst.Layers {
		dt, err := content.ReadBlob(ctx, p, l)
		if err != nil {
			return nil, err
		}
		m, err := testutil.ReadTarToMap(dt, true)
		if err != nil {
			return nil, err
		}
		ii.layers = append(ii.layers, m)
	}
	return ii, nil
}
