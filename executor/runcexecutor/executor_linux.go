package runcexecutor

import (
	"context"
	"io"
	"os"
	"path"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/containerd/continuity/fs"
	runc "github.com/containerd/go-runc"
	"github.com/docker/docker/pkg/signal"
	"github.com/moby/buildkit/executor"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func updateRuncFieldsForHostOS(runtime *runc.Runc) {
	// PdeathSignal only supported on unix platforms
	runtime.PdeathSignal = syscall.SIGKILL // this can still leak the process
}

func (w *runcExecutor) run(ctx context.Context, id, bundle string, rootfs string, process executor.ProcessInfo) error {
	return w.callWithIO(ctx, id, bundle, rootfs, process, func(ctx context.Context, started chan<- int, io runc.IO) error {
		_, err := w.runc.Run(ctx, id, bundle, &runc.CreateOpts{
			NoPivot: w.noPivot,
			Started: started,
			IO:      io,
		})
		return err
	})
}

func (w *runcExecutor) exec(ctx context.Context, id, bundle string, rootfs string, specsProcess *specs.Process, process executor.ProcessInfo) error {
	return w.callWithIO(ctx, id, bundle, rootfs, process, func(ctx context.Context, started chan<- int, io runc.IO) error {
		return w.runc.Exec(ctx, id, *specsProcess, &runc.ExecOpts{
			Started: started,
			IO:      io,
		})
	})
}

type runcCall func(ctx context.Context, started chan<- int, io runc.IO) error

func (w *runcExecutor) callWithIO(ctx context.Context, id, bundle, rootfs string, process executor.ProcessInfo, call runcCall) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !process.Meta.Tty {
		redirects := newRedirects(rootfs, process.Meta.Cwd).setup(process.Stdin, process.Stdout, process.Stderr)
		for fd, content := range process.Meta.RedirectReads {
			redirects.redirectRead(fd, content)
		}
		for fd, content := range process.Meta.RedirectWrites {
			redirects.redirectWrite(fd, content)
		}
		defer redirects.teardown()
		return call(ctx, nil, &forwardIO{stdin: redirects.stdin, stdout: redirects.stdout, stderr: redirects.stderr})
	}

	ptm, ptsName, err := console.NewPty()
	if err != nil {
		return err
	}

	pts, err := os.OpenFile(ptsName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptm.Close()
		return err
	}

	eg, ctx := errgroup.WithContext(ctx)

	defer func() {
		if process.Stdin != nil {
			process.Stdin.Close()
		}
		pts.Close()
		ptm.Close()
		cancel() // this will shutdown resize loop
		err := eg.Wait()
		if err != nil {
			logrus.Warningf("error while shutting down tty io: %s", err)
		}
	}()

	if process.Stdin != nil {
		eg.Go(func() error {
			_, err := io.Copy(ptm, process.Stdin)
			// stdin might be a pipe, so this is like EOF
			if errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		})
	}

	if process.Stdout != nil {
		eg.Go(func() error {
			_, err := io.Copy(process.Stdout, ptm)
			// ignore `read /dev/ptmx: input/output error` when ptm is closed
			var ptmClosedError *os.PathError
			if errors.As(err, &ptmClosedError) {
				if ptmClosedError.Op == "read" &&
					ptmClosedError.Path == "/dev/ptmx" &&
					ptmClosedError.Err == syscall.EIO {
					return nil
				}
			}
			return err
		})
	}

	started := make(chan int, 1)

	eg.Go(func() error {
		startedCtx, timeout := context.WithTimeout(ctx, 10*time.Second)
		defer timeout()
		var runcProcess *os.Process
		select {
		case <-startedCtx.Done():
			return errors.New("runc started message never received")
		case pid, ok := <-started:
			if !ok {
				return errors.New("runc process failed to send pid")
			}
			runcProcess, err = os.FindProcess(pid)
			if err != nil {
				return errors.Wrapf(err, "unable to find runc process for pid %d", pid)
			}
			defer runcProcess.Release()
		}

		for {
			select {
			case <-ctx.Done():
				return nil
			case resize := <-process.Resize:
				err = ptm.Resize(console.WinSize{
					Height: uint16(resize.Rows),
					Width:  uint16(resize.Cols),
				})
				if err != nil {
					logrus.Errorf("failed to resize ptm: %s", err)
				}
				err = runcProcess.Signal(signal.SIGWINCH)
				if err != nil {
					logrus.Errorf("failed to send SIGWINCH to process: %s", err)
				}
			}
		}
	})

	redirects := newRedirects(rootfs, process.Meta.Cwd).setup(pts, pts, pts)
	for fd, content := range process.Meta.RedirectReads {
		redirects.redirectRead(fd, content)
	}
	for fd, content := range process.Meta.RedirectWrites {
		redirects.redirectWrite(fd, content)
	}

	runcIO := &forwardIO{}
	if process.Stdin != nil {
		runcIO.stdin = redirects.stdin
	}
	if process.Stdout != nil {
		runcIO.stdout = redirects.stdout
	}
	if process.Stderr != nil {
		runcIO.stderr = redirects.stderr
	}

	return call(ctx, started, runcIO)
}

type redirector struct {
	root string
	cwd  string

	stdin  io.ReadCloser
	stdout io.WriteCloser
	stderr io.WriteCloser
	extra  []*os.File

	closers []io.Closer
}

func newRedirects(root string, cwd string) *redirector {
	return &redirector{
		root: root,
		cwd:  cwd,
	}
}

func (r *redirector) setup(stdin io.ReadCloser, stdout, stderr io.WriteCloser) *redirector {
	r.stdin = stdin
	r.stdout = stdout
	r.stderr = stderr
	r.extra = []*os.File{}
	return r
}

func (r *redirector) teardown() *redirector {
	for _, closer := range r.closers {
		closer.Close()
	}
	return r
}

func (r *redirector) redirectRead(fd uint32, filename string) {
	filename = path.Join(r.cwd, filename)
	filename, err := fs.RootPath(r.root, filename)
	if err != nil {
		panic(err)
	}

	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	r.closers = append(r.closers, f)

	switch fd {
	case 0:
		r.stdin = f
	case 1:
		panic("cannot use read-only file as stdout")
	case 2:
		panic("cannot use read-only file as stderr")
	default:
		idx := fd - 3
		if int(idx) >= len(r.extra) {
			r.extra = r.extra[:idx+1]
		}
		r.extra[idx] = f
	}
}

func (r *redirector) redirectWrite(fd uint32, filename string) {
	panic("unimplemented")
}
