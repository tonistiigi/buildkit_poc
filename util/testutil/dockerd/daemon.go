package dockerd

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/go-connections/sockets"
	"github.com/pkg/errors"
)

// LogT is the subset of the testing.TB interface used by the daemon.
type LogT interface {
	Logf(string, ...interface{})
}

// nopLog is a no-op implementation of LogT that is used in daemons created by
// NewDaemon (where no testing.TB is available).
type nopLog struct{}

func (nopLog) Logf(string, ...interface{}) {}

const defaultDockerdBinary = "dockerd"

// Option is used to configure a daemon.
type Option func(*Daemon)

type clientConfig struct {
	transport *http.Transport
	scheme    string
	addr      string
}

// Daemon represents a Docker daemon for the testing framework
type Daemon struct {
	root          string
	folder        string
	Wait          chan error
	id            string
	logFile       *os.File
	cmd           *exec.Cmd
	storageDriver string
	execRoot      string
	dockerdBinary string
	Log           LogT
	pidFile       string
	sockPath      string
	args          []string
}

// sockRoot holds the path of the default docker integration daemon socket
var sockRoot = filepath.Join(os.TempDir(), "docker-integration")

// NewDaemon returns a Daemon instance to be used for testing.
// The daemon will not automatically start.
// The daemon will modify and create files under workingDir.
func NewDaemon(workingDir string, ops ...Option) (*Daemon, error) {
	if err := os.MkdirAll(sockRoot, 0700); err != nil {
		return nil, errors.Wrapf(err, "failed to create daemon socket root %q", sockRoot)
	}

	id := "d" + stringid.TruncateID(stringid.GenerateRandomID())
	daemonFolder, err := filepath.Abs(filepath.Join(workingDir, id))
	if err != nil {
		return nil, err
	}
	daemonRoot := filepath.Join(daemonFolder, "root")
	if err := os.MkdirAll(daemonRoot, 0755); err != nil {
		return nil, errors.Wrapf(err, "failed to create daemon root %q", daemonRoot)
	}

	d := &Daemon{
		id:            id,
		folder:        daemonFolder,
		root:          daemonRoot,
		storageDriver: os.Getenv("DOCKER_GRAPHDRIVER"),
		// dxr stands for docker-execroot (shortened for avoiding unix(7) path length limitation)
		execRoot:      filepath.Join(os.TempDir(), "dxr", id),
		dockerdBinary: defaultDockerdBinary,
		Log:           nopLog{},
		sockPath:      filepath.Join(sockRoot, id+".sock"),
	}

	for _, op := range ops {
		op(d)
	}

	return d, nil
}

// Sock returns the socket path of the daemon
func (d *Daemon) Sock() string {
	return "unix://" + d.sockPath
}

// StartWithError starts the daemon and return once it is ready to receive requests.
// It returns an error in case it couldn't start.
func (d *Daemon) StartWithError(args ...string) error {
	logFile, err := os.OpenFile(filepath.Join(d.folder, "docker.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return errors.Wrapf(err, "[%s] failed to create logfile", d.id)
	}

	return d.StartWithLogFile(logFile, args...)
}

// StartWithLogFile will start the daemon and attach its streams to a given file.
func (d *Daemon) StartWithLogFile(out *os.File, providedArgs ...string) error {
	dockerdBinary, err := exec.LookPath(d.dockerdBinary)
	if err != nil {
		return errors.Wrapf(err, "[%s] could not find docker binary in $PATH", d.id)
	}

	if d.pidFile == "" {
		d.pidFile = filepath.Join(d.folder, "docker.pid")
	}

	d.args = []string{
		"--data-root", d.root,
		"--exec-root", d.execRoot,
		"--pidfile", d.pidFile,
		"--containerd-namespace", d.id,
		"--containerd-plugins-namespace", d.id + "p",
		"--host", d.Sock(),
	}
	if root := os.Getenv("DOCKER_REMAP_ROOT"); root != "" {
		d.args = append(d.args, "--userns-remap", root)
	}

	// If we don't explicitly set the log-level or debug flag(-D) then
	// turn on debug mode
	var foundLog, foundSd bool
	for _, a := range providedArgs {
		if strings.Contains(a, "--log-level") || strings.Contains(a, "-D") || strings.Contains(a, "--debug") {
			foundLog = true
		}
		if strings.Contains(a, "--storage-driver") {
			foundSd = true
		}
	}
	if !foundLog {
		d.args = append(d.args, "--debug")
	}
	if d.storageDriver != "" && !foundSd {
		d.args = append(d.args, "--storage-driver", d.storageDriver)
	}

	d.args = append(d.args, providedArgs...)
	d.cmd = exec.Command(dockerdBinary, d.args...)
	d.cmd.Env = append(os.Environ(), "DOCKER_SERVICE_PREFER_OFFLINE_IMAGE=1")
	d.cmd.Stdout = out
	d.cmd.Stderr = out
	d.logFile = out

	if err := d.cmd.Start(); err != nil {
		return errors.Wrapf(err, "[%s] could not start daemon container", d.id)
	}

	wait := make(chan error, 1)

	go func() {
		ret := d.cmd.Wait()
		d.Log.Logf("[%s] exiting daemon", d.id)
		// If we send before logging, we might accidentally log _after_ the test is done.
		// As of Go 1.12, this incurs a panic instead of silently being dropped.
		wait <- ret
		close(wait)
	}()

	d.Wait = wait

	clientConfig, err := d.getClientConfig()
	if err != nil {
		return err
	}
	httpClient := &http.Client{
		Transport: clientConfig.transport,
	}

	req, err := http.NewRequest(http.MethodGet, "/_ping", nil)
	if err != nil {
		return errors.Wrapf(err, "[%s] could not create new request", d.id)
	}
	req.URL.Host = clientConfig.addr
	req.URL.Scheme = clientConfig.scheme

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// make sure daemon is ready to receive requests
	for i := 0; ; i++ {
		d.Log.Logf("[%s] waiting for daemon to start", d.id)

		select {
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "[%s] daemon exited and never started", d.id)
		case err := <-d.Wait:
			return errors.Wrapf(err, "[%s] daemon exited during startup", d.id)
		default:
			rctx, rcancel := context.WithTimeout(context.TODO(), 2*time.Second)
			defer rcancel()

			resp, err := httpClient.Do(req.WithContext(rctx))
			if err != nil {
				if i > 2 { // don't log the first couple, this ends up just being noise
					d.Log.Logf("[%s] error pinging daemon on start: %v", d.id, err)
				}

				select {
				case <-ctx.Done():
				case <-time.After(500 * time.Millisecond):
				}
				continue
			}

			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				d.Log.Logf("[%s] received status != 200 OK: %s\n", d.id, resp.Status)
				return errors.Errorf("[%s] received status != 200 OK: %s\n", d.id, resp.Status)
			}
			d.Log.Logf("[%s] daemon started\n", d.id)
			return nil
		}
	}
}

var errDaemonNotStarted = errors.New("daemon not started")

// StopWithError will send a SIGINT every second and wait for the daemon to stop.
// If it timeouts, a SIGKILL is sent.
// Stop will not delete the daemon directory. If a purged daemon is needed,
// instantiate a new one with NewDaemon.
func (d *Daemon) StopWithError() (err error) {
	if d.cmd == nil || d.Wait == nil {
		return errDaemonNotStarted
	}
	defer func() {
		if err != nil {
			d.Log.Logf("[%s] error while stopping daemon: %v", d.id, err)
		} else {
			d.Log.Logf("[%s] daemon stopped", d.id)
			if d.pidFile != "" {
				_ = os.Remove(d.pidFile)
			}
		}
		if err := d.logFile.Close(); err != nil {
			d.Log.Logf("[%s] failed to close daemon logfile: %v", d.id, err)
		}
		d.cmd = nil
	}()

	i := 1
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tick := ticker.C

	d.Log.Logf("[%s] stopping daemon", d.id)

	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		if strings.Contains(err.Error(), "os: process already finished") {
			return errDaemonNotStarted
		}
		return errors.Wrapf(err, "[%s] could not send signal", d.id)
	}

out1:
	for {
		select {
		case err := <-d.Wait:
			return err
		case <-time.After(20 * time.Second):
			// time for stopping jobs and run onShutdown hooks
			d.Log.Logf("[%s] daemon stop timed out after 20 seconds", d.id)
			break out1
		}
	}

out2:
	for {
		select {
		case err := <-d.Wait:
			return err
		case <-tick:
			i++
			if i > 5 {
				d.Log.Logf("[%s] tried to interrupt daemon for %d times, now try to kill it", d.id, i)
				break out2
			}
			d.Log.Logf("[%d] attempt #%d/5: daemon is still running with pid %d", i, d.cmd.Process.Pid)
			if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
				return errors.Wrapf(err, "[%s] attempt #%d/5 could not send signal", d.id, i)
			}
		}
	}

	if err := d.cmd.Process.Kill(); err != nil {
		d.Log.Logf("[%s] failed to kill daemon: %v", d.id, err)
		return err
	}

	return nil
}

func (d *Daemon) getClientConfig() (*clientConfig, error) {
	var (
		transport = &http.Transport{}
		scheme    = "http"
		addr      = d.sockPath
		proto     = "unix"
	)
	if err := sockets.ConfigureTransport(transport, proto, addr); err != nil {
		return nil, err
	}
	transport.DisableKeepAlives = true
	return &clientConfig{
		transport: transport,
		scheme:    scheme,
		addr:      filepath.Base(addr),
	}, nil
}
