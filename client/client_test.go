package client

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/continuity/fs/fstest"
	"github.com/moby/buildkit/client/llb"
	gateway "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/secrets/secretsprovider"
	"github.com/moby/buildkit/session/sshforward/sshprovider"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/entitlements"
	"github.com/moby/buildkit/util/testutil"
	"github.com/moby/buildkit/util/testutil/echoserver"
	"github.com/moby/buildkit/util/testutil/httpserver"
	"github.com/moby/buildkit/util/testutil/integration"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sync/errgroup"
)

func init() {
	if os.Getenv("TEST_DOCKERD") == "1" {
		integration.InitDockerdWorker()
	} else {
		integration.InitOCIWorker()
		integration.InitContainerdWorker()
	}
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func TestIntegration(t *testing.T) {
	mirrors := integration.WithMirroredImages(integration.OfficialImages("busybox:latest", "alpine:latest"))

	integration.Run(t, []integration.Test{
		testCacheExportCacheKeyLoop,
		testRelativeWorkDir,
		testFileOpMkdirMkfile,
		testFileOpCopyRm,
		testFileOpRmWildcard,
		testCallDiskUsage,
		testBuildMultiMount,
		testBuildHTTPSource,
		testBuildPushAndValidate,
		testBuildExportWithUncompressed,
		testResolveAndHosts,
		testUser,
		testOCIExporter,
		testWhiteoutParentDir,
		testFrontendImageNaming,
		testDuplicateWhiteouts,
		testSchema1Image,
		testMountWithNoSource,
		testInvalidExporter,
		testReadonlyRootFS,
		testBasicRegistryCacheImportExport,
		testBasicLocalCacheImportExport,
		testCachedMounts,
		testProxyEnv,
		testLocalSymlinkEscape,
		testTmpfsMounts,
		testSharedCacheMounts,
		testLockedCacheMounts,
		testDuplicateCacheMount,
		testParallelLocalBuilds,
		testSecretMounts,
		testExtraHosts,
		testNetworkMode,
		testFrontendMetadataReturn,
		testFrontendUseSolveResults,
		testNestedLLBBuild,
		testSSHMount,
		testStdinClosed,
		testHostnameLookup,
		testPushByDigest,
		testBasicInlineCacheImportExport,
		testExportBusyboxLocal,
		testBridgeNetworking,
		testCacheMountNoCache,
		testExporterTargetExists,
		testTarExporterWithSocket,
		testTarExporterSymlink,
		testMultipleRegistryCacheImportExport,
	}, mirrors)

	integration.Run(t, []integration.Test{
		testSecurityMode,
		testSecurityModeSysfs,
		testSecurityModeErrors,
	},
		mirrors,
		integration.WithMatrix("secmode", map[string]interface{}{
			"sandbox":  securitySandbox,
			"insecure": securityInsecure,
		}),
	)

	integration.Run(t, []integration.Test{
		testHostNetworking,
	},
		mirrors,
		integration.WithMatrix("netmode", map[string]interface{}{
			"default": defaultNetwork,
			"host":    hostNetwork,
		}),
	)
}

func newContainerd(cdAddress string) (*containerd.Client, error) {
	return containerd.New(cdAddress, containerd.WithTimeout(60*time.Second), containerd.WithDefaultRuntime("io.containerd.runtime.v1.linux"))
}

// moby/buildkit#1336
func testCacheExportCacheKeyLoop(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	tmpdir, err := ioutil.TempDir("", "buildkit-buildctl")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)

	err = ioutil.WriteFile(filepath.Join(tmpdir, "foo"), []byte("foodata"), 0600)
	require.NoError(t, err)

	for _, mode := range []bool{false, true} {
		func(mode bool) {
			t.Run(fmt.Sprintf("mode=%v", mode), func(t *testing.T) {
				buildbase := llb.Image("alpine:latest").File(llb.Copy(llb.Local("mylocal"), "foo", "foo"))
				if mode { // same cache keys with a separating node go to different code-path
					buildbase = buildbase.Run(llb.Shlex("true")).Root()
				}
				intermed := llb.Image("alpine:latest").File(llb.Copy(buildbase, "foo", "foo"))
				final := llb.Scratch().File(llb.Copy(intermed, "foo", "foooooo"))

				def, err := final.Marshal(context.TODO())
				require.NoError(t, err)

				_, err = c.Solve(context.TODO(), def, SolveOpt{
					CacheExports: []CacheOptionsEntry{
						{
							Type: "local",
							Attrs: map[string]string{
								"dest": filepath.Join(tmpdir, "cache"),
							},
						},
					},
					LocalDirs: map[string]string{
						"mylocal": tmpdir,
					},
				}, nil)
				require.NoError(t, err)
			})
		}(mode)
	}
}

func testBridgeNetworking(t *testing.T, sb integration.Sandbox) {
	if os.Getenv("BUILDKIT_RUN_NETWORK_INTEGRATION_TESTS") == "" {
		t.SkipNow()
	}
	if sb.Rootless() {
		t.SkipNow()
	}
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	s, err := echoserver.NewTestServer("foo")
	require.NoError(t, err)
	addrParts := strings.Split(s.Addr().String(), ":")

	def, err := llb.Image("busybox").Run(llb.Shlexf("sh -c 'nc 127.0.0.1 %s | grep foo'", addrParts[len(addrParts)-1])).Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.Error(t, err)
}
func testHostNetworking(t *testing.T, sb integration.Sandbox) {
	if os.Getenv("BUILDKIT_RUN_NETWORK_INTEGRATION_TESTS") == "" {
		t.SkipNow()
	}
	netMode := sb.Value("netmode")
	var allowedEntitlements []entitlements.Entitlement
	if netMode == hostNetwork {
		allowedEntitlements = []entitlements.Entitlement{entitlements.EntitlementNetworkHost}
	}
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	s, err := echoserver.NewTestServer("foo")
	require.NoError(t, err)
	addrParts := strings.Split(s.Addr().String(), ":")

	def, err := llb.Image("busybox").Run(llb.Shlexf("sh -c 'nc 127.0.0.1 %s | grep foo'", addrParts[len(addrParts)-1]), llb.Network(llb.NetModeHost)).Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		AllowedEntitlements: allowedEntitlements,
	}, nil)
	if netMode == hostNetwork {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
	}
}

// #877
func testExportBusyboxLocal(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	def, err := llb.Image("busybox").Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(destDir, "bin/busybox"))
	require.NoError(t, err)

	fi2, err := os.Stat(filepath.Join(destDir, "bin/vi"))
	require.NoError(t, err)

	st1 := fi.Sys().(*syscall.Stat_t)
	st2 := fi2.Sys().(*syscall.Stat_t)

	require.Equal(t, st1.Ino, st2.Ino)
}

func testHostnameLookup(t *testing.T, sb integration.Sandbox) {
	if sb.Rootless() {
		t.SkipNow()
	}

	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").Run(llb.Shlex(`sh -c "ping -c 1 $(hostname)"`))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

// moby/buildkit#614
func testStdinClosed(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").Run(llb.Shlex("cat"))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testSSHMount(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	a := agent.NewKeyring()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	err = a.Add(agent.AddedKey{PrivateKey: k})
	require.NoError(t, err)

	sockPath, clean, err := makeSSHAgentSock(a)
	require.NoError(t, err)
	defer clean()

	ssh, err := sshprovider.NewSSHAgentProvider([]sshprovider.AgentConfig{{
		Paths: []string{sockPath},
	}})
	require.NoError(t, err)

	// no ssh exposed
	st := llb.Image("busybox:latest").Run(llb.Shlex(`nosuchcmd`), llb.AddSSHSocket())
	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no SSH key ")

	// custom ID not exposed
	st = llb.Image("busybox:latest").Run(llb.Shlex(`nosuchcmd`), llb.AddSSHSocket(llb.SSHID("customID")))
	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{ssh},
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unset ssh forward key customID")

	// missing custom ID ignored on optional
	st = llb.Image("busybox:latest").Run(llb.Shlex(`ls`), llb.AddSSHSocket(llb.SSHID("customID"), llb.SSHOptional))
	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{ssh},
	}, nil)
	require.NoError(t, err)

	// valid socket
	st = llb.Image("alpine:latest").
		Run(llb.Shlex(`apk add --no-cache openssh`)).
		Run(llb.Shlex(`sh -c 'echo -n $SSH_AUTH_SOCK > /out/sock && ssh-add -l > /out/out'`),
			llb.AddSSHSocket())

	out := st.AddMount("/out", llb.Scratch())
	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		Session: []session.Attachable{ssh},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "sock"))
	require.NoError(t, err)
	require.Equal(t, "/run/buildkit/ssh_agent.0", string(dt))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "2048")
	require.Contains(t, string(dt), "(RSA)")

	// forbidden command
	st = llb.Image("alpine:latest").
		Run(llb.Shlex(`apk add --no-cache openssh`)).
		Run(llb.Shlex(`sh -c 'ssh-keygen -f /tmp/key -N "" && ssh-add -k /tmp/key 2> /out/out || true'`),
			llb.AddSSHSocket())

	out = st.AddMount("/out", llb.Scratch())
	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		Session: []session.Attachable{ssh},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "agent refused operation")

	// valid socket from key on disk
	st = llb.Image("alpine:latest").
		Run(llb.Shlex(`apk add --no-cache openssh`)).
		Run(llb.Shlex(`sh -c 'ssh-add -l > /out/out'`),
			llb.AddSSHSocket())

	out = st.AddMount("/out", llb.Scratch())
	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	k, err = rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	dt = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		},
	)

	tmpDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	err = ioutil.WriteFile(filepath.Join(tmpDir, "key"), dt, 0600)
	require.NoError(t, err)

	ssh, err = sshprovider.NewSSHAgentProvider([]sshprovider.AgentConfig{{
		Paths: []string{filepath.Join(tmpDir, "key")},
	}})
	require.NoError(t, err)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		Session: []session.Attachable{ssh},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "1024")
	require.Contains(t, string(dt), "(RSA)")
}

func testExtraHosts(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(`sh -c 'cat /etc/hosts | grep myhost | grep 1.2.3.4'`), llb.AddExtraHost("myhost", net.ParseIP("1.2.3.4")))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testNetworkMode(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(`sh -c 'wget https://example.com 2>&1 | grep "wget: bad address"'`), llb.Network(llb.NetModeNone))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	st2 := llb.Image("busybox:latest").
		Run(llb.Shlex(`ifconfig`), llb.Network(llb.NetModeHost))

	def, err = st2.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		// Currently disabled globally by default
		// AllowedEntitlements: []entitlements.Entitlement{entitlements.EntitlementNetworkHost},
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network.host is not allowed")
}

func testPushByDigest(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	st := llb.Scratch().File(llb.Mkfile("foo", 0600, []byte("data")))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	name := registry + "/foo/bar"

	resp, err := c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: "image",
				Attrs: map[string]string{
					"name":           name,
					"push":           "true",
					"push-by-digest": "true",
				},
			},
		},
	}, nil)
	require.NoError(t, err)

	_, _, err = contentutil.ProviderFromRef(name + ":latest")
	require.Error(t, err)

	desc, _, err := contentutil.ProviderFromRef(name + "@" + resp.ExporterResponse["containerimage.digest"])
	require.NoError(t, err)

	require.Equal(t, resp.ExporterResponse["containerimage.digest"], desc.Digest.String())
	require.Equal(t, images.MediaTypeDockerSchema2Manifest, desc.MediaType)
	require.True(t, desc.Size > 0)
}

func testSecurityMode(t *testing.T, sb integration.Sandbox) {
	var command string
	mode := llb.SecurityModeSandbox
	var allowedEntitlements []entitlements.Entitlement
	secMode := sb.Value("secmode")
	if secMode == securitySandbox {
		/*
			$ capsh --decode=00000000a80425fb
			0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,
			cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
		*/
		command = `sh -c 'cat /proc/self/status | grep CapEff | grep "00000000a80425fb"'`
		allowedEntitlements = []entitlements.Entitlement{}
	} else {
		skipDockerd(t, sb)
		/*
			$ capsh --decode=0000003fffffffff
			0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,
			cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,
			cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,
			cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,
			cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
		*/
		command = `sh -c 'cat /proc/self/status | grep CapEff | grep "0000003fffffffff"'`
		mode = llb.SecurityModeInsecure
		allowedEntitlements = []entitlements.Entitlement{entitlements.EntitlementSecurityInsecure}
	}

	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(command),
			llb.Security(mode))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		AllowedEntitlements: allowedEntitlements,
	}, nil)

	require.NoError(t, err)
}

func testSecurityModeSysfs(t *testing.T, sb integration.Sandbox) {
	if sb.Rootless() {
		t.SkipNow()
	}

	mode := llb.SecurityModeSandbox
	var allowedEntitlements []entitlements.Entitlement
	secMode := sb.Value("secmode")
	if secMode == securitySandbox {
		allowedEntitlements = []entitlements.Entitlement{}
	} else {
		skipDockerd(t, sb)
		mode = llb.SecurityModeInsecure
		allowedEntitlements = []entitlements.Entitlement{entitlements.EntitlementSecurityInsecure}
	}

	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	command := `mkdir /sys/fs/cgroup/cpuset/securitytest`
	st := llb.Image("busybox:latest").
		Run(llb.Shlex(command),
			llb.Security(mode))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		AllowedEntitlements: allowedEntitlements,
	}, nil)

	if secMode == securitySandbox {
		require.Error(t, err)
		require.Contains(t, err.Error(), "executor failed running")
		require.Contains(t, err.Error(), "mkdir /sys/fs/cgroup/cpuset/securitytest")
	} else {
		require.NoError(t, err)
	}
}

func testSecurityModeErrors(t *testing.T, sb integration.Sandbox) {

	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()
	secMode := sb.Value("secmode")
	if secMode == securitySandbox {

		st := llb.Image("busybox:latest").
			Run(llb.Shlex(`sh -c 'echo sandbox'`))

		def, err := st.Marshal(context.TODO())
		require.NoError(t, err)

		_, err = c.Solve(context.TODO(), def, SolveOpt{
			AllowedEntitlements: []entitlements.Entitlement{entitlements.EntitlementSecurityInsecure},
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "security.insecure is not allowed")
	}
	if secMode == securityInsecure {
		st := llb.Image("busybox:latest").
			Run(llb.Shlex(`sh -c 'echo insecure'`), llb.Security(llb.SecurityModeInsecure))

		def, err := st.Marshal(context.TODO())
		require.NoError(t, err)

		_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "security.insecure is not allowed")
	}
}

func testFrontendImageNaming(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	checkImageName := map[string]func(out, imageName string, exporterResponse map[string]string){
		ExporterOCI: func(out, imageName string, exporterResponse map[string]string) {
			// Nothing to check
			return
		},
		ExporterDocker: func(out, imageName string, exporterResponse map[string]string) {
			require.Contains(t, exporterResponse, "image.name")
			require.Equal(t, exporterResponse["image.name"], "docker.io/library/"+imageName)

			dt, err := ioutil.ReadFile(out)
			require.NoError(t, err)

			m, err := testutil.ReadTarToMap(dt, false)
			require.NoError(t, err)

			_, ok := m["oci-layout"]
			require.True(t, ok)

			var index ocispec.Index
			err = json.Unmarshal(m["index.json"].Data, &index)
			require.NoError(t, err)
			require.Equal(t, 2, index.SchemaVersion)
			require.Equal(t, 1, len(index.Manifests))

			var dockerMfst []struct {
				RepoTags []string
			}
			err = json.Unmarshal(m["manifest.json"].Data, &dockerMfst)
			require.NoError(t, err)
			require.Equal(t, 1, len(dockerMfst))
			require.Equal(t, 1, len(dockerMfst[0].RepoTags))
			require.Equal(t, imageName, dockerMfst[0].RepoTags[0])
		},
		ExporterImage: func(_, imageName string, exporterResponse map[string]string) {
			require.Contains(t, exporterResponse, "image.name")
			require.Equal(t, exporterResponse["image.name"], imageName)

			// check if we can pull (requires containerd)
			var cdAddress string
			if cd, ok := sb.(interface {
				ContainerdAddress() string
			}); !ok {
				return
			} else {
				cdAddress = cd.ContainerdAddress()
			}

			// TODO: make public pull helper function so this can be checked for standalone as well

			client, err := containerd.New(cdAddress)
			require.NoError(t, err)
			defer client.Close()

			ctx := namespaces.WithNamespace(context.Background(), "buildkit")

			// check image in containerd
			_, err = client.ImageService().Get(ctx, imageName)
			require.NoError(t, err)

			// deleting image should release all content
			err = client.ImageService().Delete(ctx, imageName, images.SynchronousDelete())
			require.NoError(t, err)

			checkAllReleasable(t, c, sb, true)

			_, err = client.Pull(ctx, imageName)
			require.NoError(t, err)

			err = client.ImageService().Delete(ctx, imageName, images.SynchronousDelete())
			require.NoError(t, err)
		},
	}

	// A caller provided name takes precedence over one returned by the frontend. Iterate over both options.
	for _, winner := range []string{"frontend", "caller"} {
		winner := winner // capture loop variable.

		// The double layer of `t.Run` here is required so
		// that the inner-most tests (with the actual
		// functionality) have definitely completed before the
		// sandbox and registry cleanups (defered above) are run.
		t.Run(winner, func(t *testing.T) {
			for _, exp := range []string{ExporterOCI, ExporterDocker, ExporterImage} {
				exp := exp // capture loop variable.
				t.Run(exp, func(t *testing.T) {
					destDir, err := ioutil.TempDir("", "buildkit")
					require.NoError(t, err)
					defer os.RemoveAll(destDir)

					so := SolveOpt{
						Exports: []ExportEntry{
							{
								Type:  exp,
								Attrs: map[string]string{},
							},
						},
					}

					out := filepath.Join(destDir, "out.tar")

					imageName := "image-" + exp + "-fe:latest"

					switch exp {
					case ExporterOCI:
						t.Skip("oci exporter does not support named images")
					case ExporterDocker:
						outW, err := os.Create(out)
						require.NoError(t, err)
						so.Exports[0].Output = fixedWriteCloser(outW)
					case ExporterImage:
						imageName = registry + "/" + imageName
						so.Exports[0].Attrs["push"] = "true"
					}

					feName := imageName
					switch winner {
					case "caller":
						feName = "loser:latest"
						so.Exports[0].Attrs["name"] = imageName
					case "frontend":
						so.Exports[0].Attrs["name"] = "*"
					}

					frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
						res := gateway.NewResult()
						res.AddMeta("image.name", []byte(feName))
						return res, nil
					}

					resp, err := c.Build(context.TODO(), so, "", frontend, nil)
					require.NoError(t, err)

					checkImageName[exp](out, imageName, resp.ExporterResponse)
				})
			}
		})
	}

	checkAllReleasable(t, c, sb, true)
}

func testSecretMounts(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(`sh -c 'mount | grep mysecret | grep "type tmpfs" && [ "$(cat /run/secrets/mysecret)" = 'foo-secret' ]'`), llb.AddSecret("/run/secrets/mysecret"))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{secretsprovider.FromMap(map[string][]byte{
			"/run/secrets/mysecret": []byte("foo-secret"),
		})},
	}, nil)
	require.NoError(t, err)

	// test optional
	st = llb.Image("busybox:latest").
		Run(llb.Shlex(`echo secret2`), llb.AddSecret("/run/secrets/mysecret2", llb.SecretOptional))

	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{secretsprovider.FromMap(map[string][]byte{})},
	}, nil)
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	st = llb.Image("busybox:latest").
		Run(llb.Shlex(`echo secret3`), llb.AddSecret("/run/secrets/mysecret3"))

	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{secretsprovider.FromMap(map[string][]byte{})},
	}, nil)
	require.Error(t, err)

	// test id,perm,uid
	st = llb.Image("busybox:latest").
		Run(llb.Shlex(`sh -c '[ "$(stat -c "%u %g %f" /run/secrets/mysecret4)" = "1 1 81ff" ]' `), llb.AddSecret("/run/secrets/mysecret4", llb.SecretID("mysecret"), llb.SecretFileOpt(1, 1, 0777)))

	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Session: []session.Attachable{secretsprovider.FromMap(map[string][]byte{
			"mysecret": []byte("pw"),
		})},
	}, nil)
	require.NoError(t, err)
}

func testTmpfsMounts(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(`sh -c 'mount | grep /foobar | grep "type tmpfs" && touch /foobar/test'`), llb.AddMount("/foobar", llb.Scratch(), llb.Tmpfs()))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testLocalSymlinkEscape(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	test := []byte(`set -ex
[[ -L /mount/foo ]]
[[ -L /mount/sub/bar ]]
[[ -L /mount/bax ]]
[[ -f /mount/bay ]]
[[ -f /mount/sub/sub2/file ]]
[[ ! -f /mount/baz ]]
[[ ! -f /mount/etc/passwd ]]
[[ ! -f /mount/etc/group ]]
[[ $(readlink /mount/foo) == "/etc/passwd" ]]
[[ $(readlink /mount/sub/bar) == "../../../etc/group" ]]
`)

	dir, err := tmpdir(
		// point to absolute path that is not part of dir
		fstest.Symlink("/etc/passwd", "foo"),
		fstest.CreateDir("sub", 0700),
		// point outside of the dir
		fstest.Symlink("../../../etc/group", "sub/bar"),
		// regular valid symlink
		fstest.Symlink("bay", "bax"),
		// target for symlink (not requested)
		fstest.CreateFile("bay", []byte{}, 0600),
		// file with many subdirs
		fstest.CreateDir("sub/sub2", 0700),
		fstest.CreateFile("sub/sub2/file", []byte{}, 0600),
		// unused file that shouldn't be included
		fstest.CreateFile("baz", []byte{}, 0600),
		fstest.CreateFile("test.sh", test, 0700),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	local := llb.Local("mylocal", llb.FollowPaths([]string{
		"test.sh", "foo", "sub/bar", "bax", "sub/sub2/file",
	}))

	st := llb.Image("busybox:latest").
		Run(llb.Shlex(`sh /mount/test.sh`), llb.AddMount("/mount", local, llb.Readonly))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		LocalDirs: map[string]string{
			"mylocal": dir,
		},
	}, nil)
	require.NoError(t, err)
}

func testRelativeWorkDir(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	pwd := llb.Image("docker.io/library/busybox:latest").
		Dir("test1").
		Dir("test2").
		Run(llb.Shlex(`sh -c "pwd > /out/pwd"`)).
		AddMount("/out", llb.Scratch())

	def, err := pwd.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "pwd"))
	require.NoError(t, err)
	require.Equal(t, []byte("/test1/test2\n"), dt)
}

func testFileOpMkdirMkfile(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Scratch().
		File(llb.Mkdir("/foo", 0700).Mkfile("bar", 0600, []byte("contents")))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, true, fi.IsDir())

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, []byte("contents"), dt)
}

func testFileOpCopyRm(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	dir, err := tmpdir(
		fstest.CreateFile("myfile", []byte("data0"), 0600),
		fstest.CreateDir("sub", 0700),
		fstest.CreateFile("sub/foo", []byte("foo0"), 0600),
		fstest.CreateFile("sub/bar", []byte("bar0"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	dir2, err := tmpdir(
		fstest.CreateFile("file2", []byte("file2"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	st := llb.Scratch().
		File(
			llb.Copy(llb.Local("mylocal"), "myfile", "myfile2").
				Copy(llb.Local("mylocal"), "sub", "out").
				Rm("out/foo").
				Copy(llb.Local("mylocal2"), "file2", "/"))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			"mylocal":  dir,
			"mylocal2": dir2,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "myfile2"))
	require.NoError(t, err)
	require.Equal(t, []byte("data0"), dt)

	fi, err := os.Stat(filepath.Join(destDir, "out"))
	require.NoError(t, err)
	require.Equal(t, true, fi.IsDir())

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "out/bar"))
	require.NoError(t, err)
	require.Equal(t, []byte("bar0"), dt)

	_, err = os.Stat(filepath.Join(destDir, "out/foo"))
	require.Equal(t, true, errors.Is(err, os.ErrNotExist))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "file2"))
	require.NoError(t, err)
	require.Equal(t, []byte("file2"), dt)

}

func testFileOpRmWildcard(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	dir, err := tmpdir(
		fstest.CreateDir("foo", 0700),
		fstest.CreateDir("bar", 0700),
		fstest.CreateFile("foo/target", []byte("foo0"), 0600),
		fstest.CreateFile("bar/target", []byte("bar0"), 0600),
		fstest.CreateFile("bar/remaining", []byte("bar1"), 0600),
	)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	st := llb.Scratch().File(
		llb.Copy(llb.Local("mylocal"), "foo", "foo").
			Copy(llb.Local("mylocal"), "bar", "bar"),
	).File(
		llb.Rm("*/target", llb.WithAllowWildcard(true)),
	)
	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		LocalDirs: map[string]string{
			"mylocal": dir,
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "bar/remaining"))
	require.NoError(t, err)
	require.Equal(t, []byte("bar1"), dt)

	fi, err := os.Stat(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, true, fi.IsDir())

	_, err = os.Stat(filepath.Join(destDir, "foo/target"))
	require.Equal(t, true, errors.Is(err, os.ErrNotExist))

	_, err = os.Stat(filepath.Join(destDir, "bar/target"))
	require.Equal(t, true, errors.Is(err, os.ErrNotExist))
}

func testCallDiskUsage(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.DiskUsage(context.TODO())
	require.NoError(t, err)
}

func testBuildMultiMount(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	alpine := llb.Image("docker.io/library/alpine:latest")
	ls := alpine.Run(llb.Shlex("/bin/ls -l"))
	busybox := llb.Image("docker.io/library/busybox:latest")
	cp := ls.Run(llb.Shlex("/bin/cp -a /busybox/etc/passwd baz"))
	cp.AddMount("/busybox", busybox)

	def, err := cp.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)
}

func testBuildHTTPSource(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	modTime := time.Now().Add(-24 * time.Hour) // avoid falso positive with current time

	resp := httpserver.Response{
		Etag:         identity.NewID(),
		Content:      []byte("content1"),
		LastModified: &modTime,
	}

	server := httpserver.NewTestServer(map[string]httpserver.Response{
		"/foo": resp,
	})
	defer server.Close()

	// invalid URL first
	st := llb.HTTP(server.URL + "/bar")

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid response status 404")

	// first correct request
	st = llb.HTTP(server.URL + "/foo")

	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	require.Equal(t, server.Stats("/foo").AllRequests, 1)
	require.Equal(t, server.Stats("/foo").CachedRequests, 0)

	tmpdir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: tmpdir,
			},
		},
	}, nil)
	require.NoError(t, err)

	require.Equal(t, server.Stats("/foo").AllRequests, 2)
	require.Equal(t, server.Stats("/foo").CachedRequests, 1)

	dt, err := ioutil.ReadFile(filepath.Join(tmpdir, "foo"))
	require.NoError(t, err)
	require.Equal(t, []byte("content1"), dt)

	// test extra options
	st = llb.HTTP(server.URL+"/foo", llb.Filename("bar"), llb.Chmod(0741), llb.Chown(1000, 1000))

	def, err = st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: tmpdir,
			},
		},
	}, nil)
	require.NoError(t, err)

	require.Equal(t, server.Stats("/foo").AllRequests, 3)
	require.Equal(t, server.Stats("/foo").CachedRequests, 1)

	dt, err = ioutil.ReadFile(filepath.Join(tmpdir, "bar"))
	require.NoError(t, err)
	require.Equal(t, []byte("content1"), dt)

	fi, err := os.Stat(filepath.Join(tmpdir, "bar"))
	require.NoError(t, err)
	require.Equal(t, fi.ModTime().Format(http.TimeFormat), modTime.Format(http.TimeFormat))
	require.Equal(t, int(fi.Mode()&0777), 0741)

	checkAllReleasable(t, c, sb, true)

	// TODO: check that second request was marked as cached
}

func testResolveAndHosts(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "cp /etc/resolv.conf ."`)
	run(`sh -c "cp /etc/hosts ."`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "resolv.conf"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "nameserver")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "hosts"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "127.0.0.1	localhost")

}

func testUser(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest").Run(llb.Shlex(`sh -c "mkdir -m 0777 /wd"`))

	run := func(user, cmd string) {
		st = st.Run(llb.Shlex(cmd), llb.Dir("/wd"), llb.User(user))
	}

	run("daemon", `sh -c "id -nu > user"`)
	run("daemon:daemon", `sh -c "id -ng > group"`)
	run("daemon:nogroup", `sh -c "id -ng > nogroup"`)
	run("1:1", `sh -c "id -g > userone"`)

	st = st.Run(llb.Shlex("cp -a /wd/. /out/"))
	out := st.AddMount("/out", llb.Scratch())

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "user"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "daemon")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "group"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "daemon")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "nogroup"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "nogroup")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "userone"))
	require.NoError(t, err)
	require.Contains(t, string(dt), "1")

	checkAllReleasable(t, c, sb, true)
}

func testOCIExporter(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "echo -n first > foo"`)
	run(`sh -c "echo -n second > bar"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	for _, exp := range []string{ExporterOCI, ExporterDocker} {

		destDir, err := ioutil.TempDir("", "buildkit")
		require.NoError(t, err)
		defer os.RemoveAll(destDir)

		out := filepath.Join(destDir, "out.tar")
		outW, err := os.Create(out)
		require.NoError(t, err)
		target := "example.com/buildkit/testoci:latest"
		attrs := map[string]string{}
		if exp == ExporterDocker {
			attrs["name"] = target
		}
		_, err = c.Solve(context.TODO(), def, SolveOpt{
			Exports: []ExportEntry{
				{
					Type:   exp,
					Attrs:  attrs,
					Output: fixedWriteCloser(outW),
				},
			},
		}, nil)
		require.NoError(t, err)

		dt, err := ioutil.ReadFile(out)
		require.NoError(t, err)

		m, err := testutil.ReadTarToMap(dt, false)
		require.NoError(t, err)

		_, ok := m["oci-layout"]
		require.True(t, ok)

		var index ocispec.Index
		err = json.Unmarshal(m["index.json"].Data, &index)
		require.NoError(t, err)
		require.Equal(t, 2, index.SchemaVersion)
		require.Equal(t, 1, len(index.Manifests))

		var mfst ocispec.Manifest
		err = json.Unmarshal(m["blobs/sha256/"+index.Manifests[0].Digest.Hex()].Data, &mfst)
		require.NoError(t, err)
		require.Equal(t, 2, len(mfst.Layers))

		var ociimg ocispec.Image
		err = json.Unmarshal(m["blobs/sha256/"+mfst.Config.Digest.Hex()].Data, &ociimg)
		require.NoError(t, err)
		require.Equal(t, "layers", ociimg.RootFS.Type)
		require.Equal(t, 2, len(ociimg.RootFS.DiffIDs))

		_, ok = m["blobs/sha256/"+mfst.Layers[0].Digest.Hex()]
		require.True(t, ok)
		_, ok = m["blobs/sha256/"+mfst.Layers[1].Digest.Hex()]
		require.True(t, ok)

		if exp != ExporterDocker {
			continue
		}

		var dockerMfst []struct {
			Config   string
			RepoTags []string
			Layers   []string
		}
		err = json.Unmarshal(m["manifest.json"].Data, &dockerMfst)
		require.NoError(t, err)
		require.Equal(t, 1, len(dockerMfst))

		_, ok = m[dockerMfst[0].Config]
		require.True(t, ok)
		require.Equal(t, 2, len(dockerMfst[0].Layers))
		require.Equal(t, 1, len(dockerMfst[0].RepoTags))
		require.Equal(t, target, dockerMfst[0].RepoTags[0])

		for _, l := range dockerMfst[0].Layers {
			_, ok := m[l]
			require.True(t, ok)
		}
	}

	checkAllReleasable(t, c, sb, true)
}

func testFrontendMetadataReturn(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
		res := gateway.NewResult()
		res.AddMeta("frontend.returned", []byte("true"))
		res.AddMeta("not-frontend.not-returned", []byte("false"))
		res.AddMeta("frontendnot.returned.either", []byte("false"))
		return res, nil
	}

	res, err := c.Build(context.TODO(), SolveOpt{
		Exports: []ExportEntry{
			{
				Type:   ExporterOCI,
				Attrs:  map[string]string{},
				Output: fixedWriteCloser(nopWriteCloser{ioutil.Discard}),
			},
		},
	}, "", frontend, nil)
	require.NoError(t, err)
	require.Contains(t, res.ExporterResponse, "frontend.returned")
	require.Equal(t, res.ExporterResponse["frontend.returned"], "true")
	require.NotContains(t, res.ExporterResponse, "not-frontend.not-returned")
	require.NotContains(t, res.ExporterResponse, "frontendnot.returned.either")
	checkAllReleasable(t, c, sb, true)
}

func testFrontendUseSolveResults(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
		st := llb.Scratch().File(
			llb.Mkfile("foo", 0600, []byte("data")),
		)

		def, err := st.Marshal(context.TODO())
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

		st = llb.Scratch().File(
			llb.Copy(st2, "foo", "foo2"),
		)

		def, err = st.Marshal(context.TODO())
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

	_, err = c.Build(context.TODO(), SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, "", frontend, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo2"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("data"))
}

func testNestedLLBBuild(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Scratch().File(
		llb.Mkfile("foo", 0600, []byte("data")),
	)

	def, err := st.Marshal(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = llb.WriteTo(def, &buf)
	require.NoError(t, err)

	frontend := func(ctx context.Context, c gateway.Client) (*gateway.Result, error) {
		st := llb.Scratch().File(
			llb.Mkfile(pb.LLBDefinitionInput, 0600, buf.Bytes()),
		)

		st = llb.Build(st)
		def, err := st.Marshal(ctx)
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

	_, err = c.Build(context.TODO(), SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, "", frontend, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("data"))
}

func skipDockerd(t *testing.T, sb integration.Sandbox) {
	// TODO: remove me once dockerd supports the image and exporter.
	t.Helper()
	if os.Getenv("TEST_DOCKERD") == "1" {
		t.Skip("dockerd missing a required exporter, cache exporter, or entitlement")
	}
}

func testExporterTargetExists(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("busybox:latest")
	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	var mdDgst string
	res, err := c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:  ExporterOCI,
				Attrs: map[string]string{},
				Output: func(m map[string]string) (io.WriteCloser, error) {
					mdDgst = m["containerimage.digest"]
					return nil, nil
				},
			},
		},
	}, nil)
	require.NoError(t, err)
	dgst := res.ExporterResponse["containerimage.digest"]

	require.True(t, strings.HasPrefix(dgst, "sha256:"))
	require.Equal(t, dgst, mdDgst)
}

func testTarExporterWithSocket(t *testing.T, sb integration.Sandbox) {
	if os.Getenv("TEST_DOCKERD") == "1" {
		t.Skip("tar exporter is temporarily broken on dockerd")
	}

	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	alpine := llb.Image("docker.io/library/alpine:latest")
	def, err := alpine.Run(llb.Args([]string{"sh", "-c", "nc -l -s local:/socket.sock & usleep 100000; kill %1"})).Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:  ExporterTar,
				Attrs: map[string]string{},
				Output: func(m map[string]string) (io.WriteCloser, error) {
					return nopWriteCloser{ioutil.Discard}, nil
				},
			},
		},
	}, nil)
	require.NoError(t, err)
}

// moby/buildkit#1418
func testTarExporterSymlink(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "echo -n first > foo;ln -s foo bar"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:   ExporterTar,
				Output: fixedWriteCloser(&nopWriteCloser{&buf}),
			},
		},
	}, nil)
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(buf.Bytes(), false)
	require.NoError(t, err)

	item, ok := m["foo"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeReg)
	require.Equal(t, []byte("first"), item.Data)

	item, ok = m["bar"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeSymlink)
	require.Equal(t, "foo", item.Header.Linkname)
}

func testBuildExportWithUncompressed(t *testing.T, sb integration.Sandbox) {
	if os.Getenv("TEST_DOCKERD") == "1" {
		t.Skip("image exporter is missing in dockerd")
	}
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	cmd := `sh -e -c "echo uncompressed > data"`

	st := llb.Scratch()
	st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	target := registry + "/buildkit/build/exporter:withnocompressed"

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name":        target,
					"push":        "true",
					"compression": "uncompressed",
				},
			},
		},
	}, nil)
	require.NoError(t, err)

	// new layer with gzip compression
	targetImg := llb.Image(target)
	cmd = `sh -e -c "echo gzip > data"`
	st = targetImg.Run(llb.Shlex(cmd), llb.Dir("/wd")).GetMount("/wd")

	target = registry + "/buildkit/build/exporter:withcompressed"
	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name": target,
					"push": "true",
				},
			},
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
	err = client.ImageService().Delete(ctx, target, images.SynchronousDelete())
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)

	img, err := client.Pull(ctx, target)
	require.NoError(t, err)

	dt, err := content.ReadBlob(ctx, img.ContentStore(), img.Target())
	require.NoError(t, err)

	var mfst = struct {
		MediaType string `json:"mediaType,omitempty"`
		ocispec.Manifest
	}{}

	err = json.Unmarshal(dt, &mfst)
	require.NoError(t, err)
	require.Equal(t, 2, len(mfst.Layers))
	require.Equal(t, images.MediaTypeDockerSchema2Layer, mfst.Layers[0].MediaType)
	require.Equal(t, images.MediaTypeDockerSchema2LayerGzip, mfst.Layers[1].MediaType)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), ocispec.Descriptor{Digest: mfst.Layers[0].Digest})
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(dt, false)
	require.NoError(t, err)

	item, ok := m["data"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeReg)
	require.Equal(t, []byte("uncompressed"), item.Data)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), ocispec.Descriptor{Digest: mfst.Layers[1].Digest})
	require.NoError(t, err)

	m, err = testutil.ReadTarToMap(dt, true)
	require.NoError(t, err)

	item, ok = m["data"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeReg)
	require.Equal(t, []byte("gzip"), item.Data)
}

func testBuildPushAndValidate(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -e -c "mkdir -p foo/sub; echo -n first > foo/sub/bar; chmod 0741 foo;"`)
	run(`true`) // this doesn't create a layer
	run(`sh -c "echo -n second > foo/sub/baz"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	target := registry + "/buildkit/testpush:latest"

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name": target,
					"push": "true",
				},
			},
		},
	}, nil)
	require.NoError(t, err)

	// test existence of the image with next build
	firstBuild := llb.Image(target)

	def, err = firstBuild.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo/sub/bar"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("first"))

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "foo/sub/baz"))
	require.NoError(t, err)
	require.Equal(t, dt, []byte("second"))

	fi, err := os.Stat(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, 0741, int(fi.Mode()&0777))

	checkAllReleasable(t, c, sb, false)

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

	// check image in containerd
	_, err = client.ImageService().Get(ctx, target)
	require.NoError(t, err)

	// deleting image should release all content
	err = client.ImageService().Delete(ctx, target, images.SynchronousDelete())
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)

	img, err := client.Pull(ctx, target)
	require.NoError(t, err)

	desc, err := img.Config(ctx)
	require.NoError(t, err)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), desc)
	require.NoError(t, err)

	var ociimg ocispec.Image
	err = json.Unmarshal(dt, &ociimg)
	require.NoError(t, err)

	require.NotEqual(t, "", ociimg.OS)
	require.NotEqual(t, "", ociimg.Architecture)
	require.NotEqual(t, "", ociimg.Config.WorkingDir)
	require.Equal(t, "layers", ociimg.RootFS.Type)
	require.Equal(t, 2, len(ociimg.RootFS.DiffIDs))
	require.NotNil(t, ociimg.Created)
	require.True(t, time.Since(*ociimg.Created) < 2*time.Minute)
	require.Condition(t, func() bool {
		for _, env := range ociimg.Config.Env {
			if strings.HasPrefix(env, "PATH=") {
				return true
			}
		}
		return false
	})

	require.Equal(t, 3, len(ociimg.History))
	require.Contains(t, ociimg.History[0].CreatedBy, "foo/sub/bar")
	require.Contains(t, ociimg.History[1].CreatedBy, "true")
	require.Contains(t, ociimg.History[2].CreatedBy, "foo/sub/baz")
	require.False(t, ociimg.History[0].EmptyLayer)
	require.True(t, ociimg.History[1].EmptyLayer)
	require.False(t, ociimg.History[2].EmptyLayer)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), img.Target())
	require.NoError(t, err)

	var mfst = struct {
		MediaType string `json:"mediaType,omitempty"`
		ocispec.Manifest
	}{}

	err = json.Unmarshal(dt, &mfst)
	require.NoError(t, err)

	require.Equal(t, images.MediaTypeDockerSchema2Manifest, mfst.MediaType)
	require.Equal(t, 2, len(mfst.Layers))
	require.Equal(t, images.MediaTypeDockerSchema2LayerGzip, mfst.Layers[0].MediaType)
	require.Equal(t, images.MediaTypeDockerSchema2LayerGzip, mfst.Layers[1].MediaType)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), ocispec.Descriptor{Digest: mfst.Layers[0].Digest})
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(dt, true)
	require.NoError(t, err)

	item, ok := m["foo/"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeDir)
	require.Equal(t, 0741, int(item.Header.Mode&0777))

	item, ok = m["foo/sub/"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeDir)

	item, ok = m["foo/sub/bar"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeReg)
	require.Equal(t, []byte("first"), item.Data)

	_, ok = m["foo/sub/baz"]
	require.False(t, ok)

	dt, err = content.ReadBlob(ctx, img.ContentStore(), ocispec.Descriptor{Digest: mfst.Layers[1].Digest})
	require.NoError(t, err)

	m, err = testutil.ReadTarToMap(dt, true)
	require.NoError(t, err)

	item, ok = m["foo/sub/baz"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeReg)
	require.Equal(t, []byte("second"), item.Data)

	item, ok = m["foo/"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeDir)
	require.Equal(t, 0741, int(item.Header.Mode&0777))

	item, ok = m["foo/sub/"]
	require.True(t, ok)
	require.Equal(t, int32(item.Header.Typeflag), tar.TypeDir)

	_, ok = m["foo/sub/bar"]
	require.False(t, ok)
}

func testBasicCacheImportExport(t *testing.T, sb integration.Sandbox, cacheOptionsEntryImport, cacheOptionsEntryExport []CacheOptionsEntry) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "echo -n foobar > const"`)
	run(`sh -c "cat /dev/urandom | head -c 100 | sha256sum > unique"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
		CacheExports: cacheOptionsEntryExport,
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "const"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "foobar")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)

	err = c.Prune(context.TODO(), nil, PruneAll)
	require.NoError(t, err)

	checkAllRemoved(t, c, sb)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			}},
		CacheImports: cacheOptionsEntryImport,
	}, nil)
	require.NoError(t, err)

	dt2, err := ioutil.ReadFile(filepath.Join(destDir, "const"))
	require.NoError(t, err)
	require.Equal(t, string(dt2), "foobar")

	dt2, err = ioutil.ReadFile(filepath.Join(destDir, "unique"))
	require.NoError(t, err)
	require.Equal(t, string(dt), string(dt2))
}

func testBasicRegistryCacheImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)
	target := registry + "/buildkit/testexport:latest"
	o := CacheOptionsEntry{
		Type: "registry",
		Attrs: map[string]string{
			"ref": target,
		},
	}
	testBasicCacheImportExport(t, sb, []CacheOptionsEntry{o}, []CacheOptionsEntry{o})
}

func testMultipleRegistryCacheImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)
	target := registry + "/buildkit/testexport:latest"
	o := CacheOptionsEntry{
		Type: "registry",
		Attrs: map[string]string{
			"ref": target,
		},
	}
	o2 := CacheOptionsEntry{
		Type: "registry",
		Attrs: map[string]string{
			"ref": target + "notexist",
		},
	}
	testBasicCacheImportExport(t, sb, []CacheOptionsEntry{o, o2}, []CacheOptionsEntry{o})
}

func testBasicLocalCacheImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	dir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	im := CacheOptionsEntry{
		Type: "local",
		Attrs: map[string]string{
			"src": dir,
		},
	}
	ex := CacheOptionsEntry{
		Type: "local",
		Attrs: map[string]string{
			"dest": dir,
		},
	}
	testBasicCacheImportExport(t, sb, []CacheOptionsEntry{im}, []CacheOptionsEntry{ex})
}

func testBasicInlineCacheImportExport(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	registry, err := sb.NewRegistry()
	if errors.Is(err, integration.ErrorRequirements) {
		t.Skip(err.Error())
	}
	require.NoError(t, err)

	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "echo -n foobar > const"`)
	run(`sh -c "cat /dev/urandom | head -c 100 | sha256sum > unique"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	target := registry + "/buildkit/testexportinline:latest"

	resp, err := c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name": target,
					"push": "true",
				},
			},
		},
		CacheExports: []CacheOptionsEntry{
			{
				Type: "inline",
			},
		},
	}, nil)
	require.NoError(t, err)

	dgst, ok := resp.ExporterResponse["containerimage.digest"]
	require.Equal(t, ok, true)

	unique, err := readFileInImage(c, target+"@"+dgst, "/unique")
	require.NoError(t, err)

	err = c.Prune(context.TODO(), nil, PruneAll)
	require.NoError(t, err)

	checkAllRemoved(t, c, sb)

	resp, err = c.Solve(context.TODO(), def, SolveOpt{
		// specifying inline cache exporter is needed for reproducing containerimage.digest
		// (not needed for reproducing rootfs/unique)
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name": target,
					"push": "true",
				},
			},
		},
		CacheExports: []CacheOptionsEntry{
			{
				Type: "inline",
			},
		},
		CacheImports: []CacheOptionsEntry{
			{
				Type: "registry",
				Attrs: map[string]string{
					"ref": target,
				},
			},
		},
	}, nil)
	require.NoError(t, err)

	dgst2, ok := resp.ExporterResponse["containerimage.digest"]
	require.Equal(t, ok, true)

	require.Equal(t, dgst, dgst2)

	err = c.Prune(context.TODO(), nil, PruneAll)
	require.NoError(t, err)

	checkAllRemoved(t, c, sb)

	resp, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type: ExporterImage,
				Attrs: map[string]string{
					"name": target,
					"push": "true",
				},
			},
		},
		CacheImports: []CacheOptionsEntry{
			{
				Type: "registry",
				Attrs: map[string]string{
					"ref": target,
				},
			},
		},
	}, nil)
	require.NoError(t, err)

	dgst3, ok := resp.ExporterResponse["containerimage.digest"]
	require.Equal(t, ok, true)

	// dgst3 != dgst, because inline cache is not exported for dgst3
	unique3, err := readFileInImage(c, target+"@"+dgst3, "/unique")
	require.NoError(t, err)
	require.EqualValues(t, unique, unique3)
}

func readFileInImage(c *Client, ref, path string) ([]byte, error) {
	def, err := llb.Image(ref).Marshal(context.TODO())
	if err != nil {
		return nil, err
	}
	destDir, err := ioutil.TempDir("", "buildkit")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadFile(filepath.Join(destDir, filepath.Clean(path)))
}

func testCachedMounts(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	// setup base for one of the cache sources
	st := busybox.Run(llb.Shlex(`sh -c "echo -n base > baz"`), llb.Dir("/wd"))
	base := st.AddMount("/wd", llb.Scratch())

	st = busybox.Run(llb.Shlex(`sh -c "echo -n first > foo"`), llb.Dir("/wd"))
	st.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountShared))
	st = st.Run(llb.Shlex(`sh -c "cat foo && echo -n second > /wd2/bar"`), llb.Dir("/wd"))
	st.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountShared))
	st.AddMount("/wd2", base, llb.AsPersistentCacheDir("mycache2", llb.CacheMountShared))

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	// repeat to make sure cache works
	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	// second build using cache directories
	st = busybox.Run(llb.Shlex(`sh -c "cp /src0/foo . && cp /src1/bar . && cp /src1/baz ."`), llb.Dir("/wd"))
	out := st.AddMount("/wd", llb.Scratch())
	st.AddMount("/src0", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountShared))
	st.AddMount("/src1", base, llb.AsPersistentCacheDir("mycache2", llb.CacheMountShared))

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "foo"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "first")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "bar"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "second")

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "baz"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "base")

	checkAllReleasable(t, c, sb, true)
}

func testSharedCacheMounts(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := busybox.Run(llb.Shlex(`sh -e -c "touch one; while [[ ! -f two ]]; do ls -l; usleep 500000; done"`), llb.Dir("/wd"))
	st.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountShared))

	st2 := busybox.Run(llb.Shlex(`sh -e -c "touch two; while [[ ! -f one ]]; do ls -l; usleep 500000; done"`), llb.Dir("/wd"))
	st2.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountShared))

	out := busybox.Run(llb.Shlex("true"))
	out.AddMount("/m1", st.Root())
	out.AddMount("/m2", st2.Root())

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testLockedCacheMounts(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := busybox.Run(llb.Shlex(`sh -e -c "touch one; if [[ -f two ]]; then exit 0; fi; for i in $(seq 10); do if [[ -f two ]]; then exit 1; fi; usleep 200000; done"`), llb.Dir("/wd"))
	st.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))

	st2 := busybox.Run(llb.Shlex(`sh -e -c "touch two; if [[ -f one ]]; then exit 0; fi; for i in $(seq 10); do if [[ -f one ]]; then exit 1; fi; usleep 200000; done"`), llb.Dir("/wd"))
	st2.AddMount("/wd", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))

	out := busybox.Run(llb.Shlex("true"))
	out.AddMount("/m1", st.Root())
	out.AddMount("/m2", st2.Root())

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testDuplicateCacheMount(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")

	out := busybox.Run(llb.Shlex(`sh -e -c "[[ ! -f /m2/foo ]]; touch /m1/foo; [[ -f /m2/foo ]];"`))
	out.AddMount("/m1", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))
	out.AddMount("/m2", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

func testCacheMountNoCache(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")

	out := busybox.Run(llb.Shlex(`sh -e -c "touch /m1/foo; touch /m2/bar"`))
	out.AddMount("/m1", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))
	out.AddMount("/m2", llb.Scratch(), llb.AsPersistentCacheDir("mycache2", llb.CacheMountLocked))

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	out = busybox.Run(llb.Shlex(`sh -e -c "[[ ! -f /m1/foo ]]; touch /m1/foo2;"`), llb.IgnoreCache)
	out.AddMount("/m1", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))

	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	out = busybox.Run(llb.Shlex(`sh -e -c "[[ -f /m1/foo2 ]]; [[ -f /m2/bar ]];"`))
	out.AddMount("/m1", llb.Scratch(), llb.AsPersistentCacheDir("mycache1", llb.CacheMountLocked))
	out.AddMount("/m2", llb.Scratch(), llb.AsPersistentCacheDir("mycache2", llb.CacheMountLocked))

	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)
}

// containerd/containerd#2119
func testDuplicateWhiteouts(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -e -c "mkdir -p d0 d1; echo -n first > d1/bar;"`)
	run(`sh -c "rm -rf d0 d1"`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	out := filepath.Join(destDir, "out.tar")
	outW, err := os.Create(out)
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:   ExporterOCI,
				Output: fixedWriteCloser(outW),
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(out)
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(dt, false)
	require.NoError(t, err)

	var index ocispec.Index
	err = json.Unmarshal(m["index.json"].Data, &index)
	require.NoError(t, err)

	var mfst ocispec.Manifest
	err = json.Unmarshal(m["blobs/sha256/"+index.Manifests[0].Digest.Hex()].Data, &mfst)
	require.NoError(t, err)

	lastLayer := mfst.Layers[len(mfst.Layers)-1]

	layer, ok := m["blobs/sha256/"+lastLayer.Digest.Hex()]
	require.True(t, ok)

	m, err = testutil.ReadTarToMap(layer.Data, true)
	require.NoError(t, err)

	_, ok = m[".wh.d0"]
	require.True(t, ok)

	_, ok = m[".wh.d1"]
	require.True(t, ok)

	// check for a bug that added whiteout for subfile
	_, ok = m["d1/.wh.bar"]
	require.True(t, !ok)
}

// #276
func testWhiteoutParentDir(t *testing.T, sb integration.Sandbox) {
	skipDockerd(t, sb)
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("busybox:latest")
	st := llb.Scratch()

	run := func(cmd string) {
		st = busybox.Run(llb.Shlex(cmd), llb.Dir("/wd")).AddMount("/wd", st)
	}

	run(`sh -c "mkdir -p foo; echo -n first > foo/bar;"`)
	run(`rm foo/bar`)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	out := filepath.Join(destDir, "out.tar")
	outW, err := os.Create(out)
	require.NoError(t, err)
	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:   ExporterOCI,
				Output: fixedWriteCloser(outW),
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(out)
	require.NoError(t, err)

	m, err := testutil.ReadTarToMap(dt, false)
	require.NoError(t, err)

	var index ocispec.Index
	err = json.Unmarshal(m["index.json"].Data, &index)
	require.NoError(t, err)

	var mfst ocispec.Manifest
	err = json.Unmarshal(m["blobs/sha256/"+index.Manifests[0].Digest.Hex()].Data, &mfst)
	require.NoError(t, err)

	lastLayer := mfst.Layers[len(mfst.Layers)-1]

	layer, ok := m["blobs/sha256/"+lastLayer.Digest.Hex()]
	require.True(t, ok)

	m, err = testutil.ReadTarToMap(layer.Data, true)
	require.NoError(t, err)

	_, ok = m["foo/.wh.bar"]
	require.True(t, ok)

	_, ok = m["foo/"]
	require.True(t, ok)
}

// #296
func testSchema1Image(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	st := llb.Image("gcr.io/google_containers/pause:3.0@sha256:0d093c962a6c2dd8bb8727b661e2b5f13e9df884af9945b4cc7088d9350cd3ee")

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)
}

// #319
func testMountWithNoSource(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("docker.io/library/busybox:latest")
	st := llb.Scratch()

	var nilState llb.State

	// This should never actually be run, but we want to succeed
	// if it was, because we expect an error below, or a daemon
	// panic if the issue has regressed.
	run := busybox.Run(
		llb.Args([]string{"/bin/true"}),
		llb.AddMount("/nil", nilState, llb.SourcePath("/"), llb.Readonly))

	st = run.AddMount("/mnt", st)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.NoError(t, err)

	checkAllReleasable(t, c, sb, true)
}

// #324
func testReadonlyRootFS(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	busybox := llb.Image("docker.io/library/busybox:latest")
	st := llb.Scratch()

	// The path /foo should be unwriteable.
	run := busybox.Run(
		llb.ReadonlyRootFS(),
		llb.Args([]string{"/bin/touch", "/foo"}))
	st = run.AddMount("/mnt", st)

	def, err := st.Marshal(context.TODO())
	require.NoError(t, err)

	_, err = c.Solve(context.TODO(), def, SolveOpt{}, nil)
	require.Error(t, err)
	// Would prefer to detect more specifically "Read-only file
	// system" but that isn't exposed here (it is on the stdio
	// which we don't see).
	require.Contains(t, err.Error(), "executor failed running [/bin/touch /foo]:")

	checkAllReleasable(t, c, sb, true)
}

func testProxyEnv(t *testing.T, sb integration.Sandbox) {
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	base := llb.Image("docker.io/library/busybox:latest").Dir("/out")
	cmd := `sh -c "echo -n $HTTP_PROXY-$HTTPS_PROXY-$NO_PROXY-$no_proxy > env"`

	st := base.Run(llb.Shlex(cmd), llb.WithProxy(llb.ProxyEnv{
		HttpProxy:  "httpvalue",
		HttpsProxy: "httpsvalue",
		NoProxy:    "noproxyvalue",
	}))
	out := st.AddMount("/out", llb.Scratch())

	def, err := out.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err := ioutil.ReadFile(filepath.Join(destDir, "env"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "httpvalue-httpsvalue-noproxyvalue-noproxyvalue")

	// repeat to make sure proxy doesn't change cache
	st = base.Run(llb.Shlex(cmd), llb.WithProxy(llb.ProxyEnv{
		HttpsProxy: "httpsvalue2",
		NoProxy:    "noproxyvalue2",
	}))
	out = st.AddMount("/out", llb.Scratch())

	def, err = out.Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err = ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:      ExporterLocal,
				OutputDir: destDir,
			},
		},
	}, nil)
	require.NoError(t, err)

	dt, err = ioutil.ReadFile(filepath.Join(destDir, "env"))
	require.NoError(t, err)
	require.Equal(t, string(dt), "httpvalue-httpsvalue-noproxyvalue-noproxyvalue")
}

func requiresLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("unsupported GOOS: %s", runtime.GOOS)
	}
}

func checkAllRemoved(t *testing.T, c *Client, sb integration.Sandbox) {
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

func checkAllReleasable(t *testing.T, c *Client, sb integration.Sandbox, checkContent bool) {
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

	err := c.Prune(context.TODO(), nil, PruneAll)
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

func testInvalidExporter(t *testing.T, sb integration.Sandbox) {
	requiresLinux(t)
	c, err := New(context.TODO(), sb.Address())
	require.NoError(t, err)
	defer c.Close()

	def, err := llb.Image("busybox:latest").Marshal(context.TODO())
	require.NoError(t, err)

	destDir, err := ioutil.TempDir("", "buildkit")
	require.NoError(t, err)
	defer os.RemoveAll(destDir)

	target := "example.com/buildkit/testoci:latest"
	attrs := map[string]string{
		"name": target,
	}
	for _, exp := range []string{ExporterOCI, ExporterDocker} {
		_, err = c.Solve(context.TODO(), def, SolveOpt{
			Exports: []ExportEntry{
				{
					Type:  exp,
					Attrs: attrs,
				},
			},
		}, nil)
		// output file writer is required
		require.Error(t, err)
		_, err = c.Solve(context.TODO(), def, SolveOpt{
			Exports: []ExportEntry{
				{
					Type:      exp,
					Attrs:     attrs,
					OutputDir: destDir,
				},
			},
		}, nil)
		// output directory is not supported
		require.Error(t, err)
	}

	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:  ExporterLocal,
				Attrs: attrs,
			},
		},
	}, nil)
	// output directory is required
	require.Error(t, err)

	f, err := os.Create(filepath.Join(destDir, "a"))
	require.NoError(t, err)
	defer f.Close()
	_, err = c.Solve(context.TODO(), def, SolveOpt{
		Exports: []ExportEntry{
			{
				Type:   ExporterLocal,
				Attrs:  attrs,
				Output: fixedWriteCloser(f),
			},
		},
	}, nil)
	// output file writer is not supported
	require.Error(t, err)

	checkAllReleasable(t, c, sb, true)
}

// moby/buildkit#492
func testParallelLocalBuilds(t *testing.T, sb integration.Sandbox) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	c, err := New(ctx, sb.Address())
	require.NoError(t, err)
	defer c.Close()

	eg, ctx := errgroup.WithContext(ctx)

	for i := 0; i < 3; i++ {
		func(i int) {
			eg.Go(func() error {
				fn := fmt.Sprintf("test%d", i)
				srcDir, err := tmpdir(
					fstest.CreateFile(fn, []byte("contents"), 0600),
				)
				require.NoError(t, err)
				defer os.RemoveAll(srcDir)

				def, err := llb.Local("source").Marshal(context.TODO())
				require.NoError(t, err)

				destDir, err := ioutil.TempDir("", "buildkit")
				require.NoError(t, err)
				defer os.RemoveAll(destDir)

				_, err = c.Solve(ctx, def, SolveOpt{
					Exports: []ExportEntry{
						{
							Type:      ExporterLocal,
							OutputDir: destDir,
						},
					},
					LocalDirs: map[string]string{
						"source": srcDir,
					},
				}, nil)
				require.NoError(t, err)

				act, err := ioutil.ReadFile(filepath.Join(destDir, fn))
				require.NoError(t, err)

				require.Equal(t, "contents", string(act))
				return nil
			})
		}(i)
	}

	err = eg.Wait()
	require.NoError(t, err)
}

func tmpdir(appliers ...fstest.Applier) (string, error) {
	tmpdir, err := ioutil.TempDir("", "buildkit-client")
	if err != nil {
		return "", err
	}
	if err := fstest.Apply(appliers...).Apply(tmpdir); err != nil {
		return "", err
	}
	return tmpdir, nil
}

func makeSSHAgentSock(agent agent.Agent) (p string, cleanup func() error, err error) {
	tmpDir, err := ioutil.TempDir("", "buildkit")
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tmpDir)
		}
	}()

	sockPath := filepath.Join(tmpDir, "ssh_auth_sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return "", nil, err
	}

	s := &server{l: l}
	go s.run(agent)

	return sockPath, func() error {
		l.Close()
		return os.RemoveAll(tmpDir)
	}, nil
}

type server struct {
	l net.Listener
}

func (s *server) run(a agent.Agent) error {
	for {
		c, err := s.l.Accept()
		if err != nil {
			return err
		}

		go agent.ServeAgent(a, c)
	}
}

type secModeSandbox struct{}

func (*secModeSandbox) UpdateConfigFile(in string) string {
	return in
}

type secModeInsecure struct{}

func (*secModeInsecure) UpdateConfigFile(in string) string {
	return in + "\n\ninsecure-entitlements = [\"security.insecure\"]\n"
}

var securitySandbox integration.ConfigUpdater = &secModeSandbox{}
var securityInsecure integration.ConfigUpdater = &secModeInsecure{}

type netModeHost struct{}

func (*netModeHost) UpdateConfigFile(in string) string {
	return in + "\n\ninsecure-entitlements = [\"network.host\"]\n"
}

type netModeDefault struct{}

func (*netModeDefault) UpdateConfigFile(in string) string {
	return in
}

var hostNetwork integration.ConfigUpdater = &netModeHost{}
var defaultNetwork integration.ConfigUpdater = &netModeDefault{}

func fixedWriteCloser(wc io.WriteCloser) func(map[string]string) (io.WriteCloser, error) {
	return func(map[string]string) (io.WriteCloser, error) {
		return wc, nil
	}
}
