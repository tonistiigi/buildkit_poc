// +build !windows

package cache

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/containerd/containerd/archive"
	ctdcompression "github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/continuity/devices"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/continuity/sysx"
	"github.com/moby/buildkit/session"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const containerdUpperDirLabelKey = "containerd.io/snapshot/overlay.upperdir"

var emptyDesc = ocispec.Descriptor{}

func (sr *immutableRef) computeOverlayBlob(ctx context.Context, mediaType string, ref string, s session.Group) (_ ocispec.Descriptor, err error) {
	sinfo, err := sr.cm.Snapshotter.Stat(ctx, getSnapshotID(sr.md))
	if err != nil {
		return emptyDesc, err
	}
	upper, ok := sinfo.Labels[containerdUpperDirLabelKey]
	if !ok {
		return emptyDesc, fmt.Errorf("upper directory is not registered")
	}

	var isCompressed bool
	switch mediaType {
	case ocispec.MediaTypeImageLayer:
	case ocispec.MediaTypeImageLayerGzip:
		isCompressed = true
	default:
		return emptyDesc, fmt.Errorf("unsupported diff media type: %v", mediaType)
	}

	cw, err := sr.cm.ContentStore.Writer(ctx,
		content.WithRef(ref),
		content.WithDescriptor(ocispec.Descriptor{
			MediaType: mediaType, // most contentstore implementations just ignore this
		}))
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to open writer")
	}
	defer func() {
		if err != nil {
			cw.Close()
		}
	}()

	var lower []mount.Mount
	if sr.parent != nil {
		m, err := sr.parent.Mount(ctx, true, s)
		if err != nil {
			return emptyDesc, err
		}
		var release func() error
		lower, release, err = m.Mount()
		if err != nil {
			return emptyDesc, err
		}
		if release != nil {
			defer release()
		}
	}

	var labels map[string]string
	if isCompressed {
		dgstr := digest.SHA256.Digester()
		compressed, err := ctdcompression.CompressStream(cw, ctdcompression.Gzip)
		if err != nil {
			return emptyDesc, errors.Wrap(err, "failed to get compressed stream")
		}
		err = writeOverlayUpperdir(ctx, io.MultiWriter(compressed, dgstr.Hash()), upper, lower)
		compressed.Close()
		if err != nil {
			return emptyDesc, errors.Wrap(err, "failed to write compressed diff")
		}
		if labels == nil {
			labels = map[string]string{}
		}
		labels[containerdUncompressed] = dgstr.Digest().String()
	} else {
		if err = writeOverlayUpperdir(ctx, cw, upper, lower); err != nil {
			return emptyDesc, errors.Wrap(err, "failed to write diff")
		}
	}

	var commitopts []content.Opt
	if labels != nil {
		commitopts = append(commitopts, content.WithLabels(labels))
	}
	dgst := cw.Digest()
	if err := cw.Commit(ctx, 0, dgst, commitopts...); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return emptyDesc, errors.Wrap(err, "failed to commit")
		}
	}
	cinfo, err := sr.cm.ContentStore.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to get info from content store")
	}
	if cinfo.Labels == nil {
		cinfo.Labels = make(map[string]string)
	}
	// Set uncompressed label if digest already existed without label
	if _, ok := cinfo.Labels[containerdUncompressed]; !ok {
		cinfo.Labels[containerdUncompressed] = labels[containerdUncompressed]
		if _, err := sr.cm.ContentStore.Update(ctx, cinfo, "labels."+containerdUncompressed); err != nil {
			return emptyDesc, errors.Wrap(err, "error setting uncompressed label")
		}
	}

	return ocispec.Descriptor{
		MediaType: mediaType,
		Size:      cinfo.Size,
		Digest:    cinfo.Digest,
	}, nil
}

func writeOverlayUpperdir(ctx context.Context, w io.Writer, upper string, lower []mount.Mount) error {
	cw := archive.NewChangeWriter(w, upper)
	changeFn := cw.HandleChange
	err := mount.WithTempMount(ctx, lower, func(lowerRoot string) error {
		return fs.DiffDirChanges(ctx, changeFn, lowerRoot, &fs.DiffDirOptions{
			DiffDir:      upper,
			DeleteChange: overlayDeleteChange,
		})
	})
	if err != nil {
		return err
	}
	return cw.Close()
}

func overlayDeleteChange(diffDir string, path string, base string, f os.FileInfo) (deleteFile string, skip bool, err error) {
	// Check if this is a whiteout
	if f.Mode()&os.ModeCharDevice != 0 {
		if _, ok := f.Sys().(*syscall.Stat_t); ok {
			maj, min, err := devices.DeviceInfo(f)
			if err != nil {
				return "", false, err
			}
			if maj == 0 && min == 0 {
				// This file is deleted from base directory
				if _, err := os.Lstat(filepath.Join(base, path)); err != nil {
					if !os.IsNotExist(err) {
						return "", false, err
					}
					// This file doesn't exist even in the base dir. We don't need whiteout. Just skip this file.
					return "", true, nil
				}
				return path, false, nil
			}
		}
	}

	// Check if this is an opaque directory
	if f.IsDir() {
		for _, oKey := range []string{"trusted.overlay.opaque", "user.overlay.opaque"} {
			opaque, err := sysx.LGetxattr(filepath.Join(diffDir, path), oKey)
			if err != nil && err != unix.ENODATA {
				return "", false, errors.Wrapf(err, "failed to retrieve trusted.overlay.opaque attr")
			} else if len(opaque) == 1 && opaque[0] == 'y' {
				// Add this directory and an opaque whiteout file.
				if _, err := os.Lstat(filepath.Join(base, path)); err != nil {
					if !os.IsNotExist(err) {
						return "", false, err
					}
					// This file doesn't exist even in the base dir. We don't need whiteout.
					// But this directory needs to be created.
					return "", false, nil
				}
				// NOTE: This is a hack to let HandleChange create an opaque entry (".wh..wh..opq").
				//       HandleChange creates a whiteout named "<path>/.wh.<filename>" so we pass ".wh..opq" as filename here.
				return filepath.Join(path, ".wh..opq"), false, nil
			}
		}
	}

	return "", false, nil
}
