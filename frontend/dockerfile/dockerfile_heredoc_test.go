// +build dfheredoc

package dockerfile

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/continuity/fs/fstest"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/frontend/dockerfile/builder"
	"github.com/moby/buildkit/util/testutil/integration"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

var hdTests = []integration.Test{
	testCopyHeredoc,
	testRunBasicHeredoc,
	testRunFakeHeredoc,
	testRunShebangHeredoc,
	testRunShebangHeredocNoShell,
	testRunComplexHeredoc,
	testHeredocIndent,
	testHeredocVarSubstitution,
	testOnBuildHeredoc,
}

func init() {
	heredocTests = append(heredocTests, hdTests...)
}

func testCopyHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

RUN adduser -D user
WORKDIR /dest

COPY <<EOF single
single file
EOF

COPY <<EOF <<EOF2 double/
first file
EOF
second file
EOF2

RUN mkdir -p /permfiles
COPY --chmod=777 <<EOF /permfiles/all
dummy content
EOF
COPY --chmod=0644 <<EOF /permfiles/rw
dummy content
EOF
COPY --chown=user:user <<EOF /permfiles/owned
dummy content
EOF
RUN stat -c "%04a" /permfiles/all >> perms && \
	stat -c "%04a" /permfiles/rw >> perms && \
	stat -c "%U:%G" /permfiles/owned >> perms

FROM scratch
COPY --from=build /dest /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	contents := map[string]string{
		"single":      "single file\n",
		"double/EOF":  "first file\n",
		"double/EOF2": "second file\n",
		"perms":       "0777\n0644\nuser:user\n",
	}

	for name, content := range contents {
		dt, err := ioutil.ReadFile(filepath.Join(destDir, name))
		require.NoError(t, err)
		require.Equal(t, content, string(dt))
	}
}

func testRunBasicHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

RUN <<EOF
echo "i am" >> /dest
whoami >> /dest
EOF

FROM scratch
COPY --from=build /dest /dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest"))
	require.NoError(t, err)
	require.Equal(t, "i am\nroot\n", string(dt))
}

func testRunFakeHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

SHELL ["/bin/awk"]
RUN <<EOF
BEGIN {
	print "foo" > "/dest"
}
EOF

FROM scratch
COPY --from=build /dest /dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest"))
	require.NoError(t, err)
	require.Equal(t, "foo\n", string(dt))
}

func testRunShebangHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

RUN <<EOF
#!/bin/awk -f
BEGIN {
	print "hello" >> "/dest"
	print "world" >> "/dest"
}
EOF

FROM scratch
COPY --from=build /dest /dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest"))
	require.NoError(t, err)
	require.Equal(t, "hello\nworld\n", string(dt))
}

func testRunShebangHeredocNoShell(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

SHELL ["/bin/non-existent"]

RUN <<EOF
#!/bin/sh
echo "still works" > /dest
EOF

FROM scratch
COPY --from=build /dest /dest
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest"))
	require.NoError(t, err)
	require.Equal(t, "still works\n", string(dt))
}

func testRunComplexHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

WORKDIR /dest

RUN cat <<EOF1 | tr '[:upper:]' '[:lower:]' > ./out1; \
	cat <<EOF2 | tr '[:lower:]' '[:upper:]' > ./out2
hello WORLD
EOF1
HELLO world
EOF2

RUN <<EOF 3<<IN1 4<<IN2 awk -f -
BEGIN {
	while ((getline line < "/proc/self/fd/3") > 0)
		print tolower(line) > "./fd3"
	while ((getline line < "/proc/self/fd/4") > 0)
		print toupper(line) > "./fd4"
}
EOF
hello WORLD
IN1
HELLO world
IN2

FROM scratch
COPY --from=build /dest /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	contents := map[string]string{
		"out1": "hello world\n",
		"out2": "HELLO WORLD\n",
		"fd3":  "hello world\n",
		"fd4":  "HELLO WORLD\n",
	}

	for name, content := range contents {
		dt, err := ioutil.ReadFile(filepath.Join(destDir, name))
		require.NoError(t, err)
		require.Equal(t, content, string(dt))
	}
}

func testHeredocIndent(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox AS build

COPY <<EOF /dest/foo-copy
	foo
EOF

COPY <<-EOF /dest/bar-copy
	bar
EOF

RUN <<EOF
echo "
	foo" > /dest/foo-run
EOF

RUN <<-EOF
echo "
	bar" > /dest/bar-run
EOF

RUN <<EOF
#!/bin/sh
echo "
	foo" > /dest/foo2-run
EOF

RUN <<-EOF
#!/bin/sh
echo "
	bar" > /dest/bar2-run
EOF

RUN <<EOF sh > /dest/foo3-run
echo "
	foo"
EOF

RUN <<-EOF sh > /dest/bar3-run
echo "
	bar"
EOF

FROM scratch
COPY --from=build /dest /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	contents := map[string]string{
		"foo-copy": "\tfoo\n",
		"foo-run":  "\n\tfoo\n",
		"foo2-run": "\n\tfoo\n",
		"foo3-run": "\n\tfoo\n",
		"bar-copy": "bar\n",
		"bar-run":  "\nbar\n",
		"bar2-run": "\nbar\n",
		"bar3-run": "\nbar\n",
	}

	for name, content := range contents {
		dt, err := ioutil.ReadFile(filepath.Join(destDir, name))
		require.NoError(t, err)
		require.Equal(t, content, string(dt))
	}
}

func testHeredocVarSubstitution(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	dockerfile := []byte(`
FROM busybox as build

ARG name=world

COPY <<EOF /dest/c1
Hello ${name}!
EOF
COPY <<'EOF' /dest/c2
Hello ${name}!
EOF
COPY <<"EOF" /dest/c3
Hello ${name}!
EOF

RUN <<EOF
greeting="Hello"
echo "${greeting} ${name}!" > /dest/r1
EOF
RUN <<EOF
name="new world"
echo "Hello ${name}!" > /dest/r2
EOF

FROM scratch
COPY --from=build /dest /
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", []byte(dockerfile), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	contents := map[string]string{
		"c1": "Hello world!\n",
		"c2": "Hello ${name}!\n",
		"c3": "Hello ${name}!\n",
		"r1": "Hello world!\n",
		"r2": "Hello new world!\n",
	}

	for name, content := range contents {
		dt, err := ioutil.ReadFile(filepath.Join(destDir, name))
		require.NoError(t, err)
		require.Equal(t, content, string(dt))
	}
}

func testOnBuildHeredoc(t *testing.T, sb integration.Sandbox) {
	f := getFrontend(t, sb)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	dockerfile := []byte(`
FROM busybox
ONBUILD RUN <<EOF
echo "hello world" >> /dest
EOF
`)

	dir, err := tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	c, err := client.New(sb.Context(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	target := registry + "/buildkit/testonbuildheredoc:base"
	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dockerfile = []byte(fmt.Sprintf(`
	FROM %s AS base
	FROM scratch
	COPY --from=base /dest /dest
	`, target))

	dir, err = tmpdir(
		fstest.CreateFile("Dockerfile", dockerfile, 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = f.Solve(sb.Context(), c, client.SolveOpt{
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

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "dest"))
	require.NoError(t, err)
	require.Equal(t, "hello world\n", string(dt))
}
