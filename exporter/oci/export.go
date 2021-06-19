package oci

import (
	"context"
	"strconv"
	"strings"
	"time"

	archiveexporter "github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/leases"
	"github.com/docker/distribution/reference"
	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/exporter"
	"github.com/moby/buildkit/exporter/containerimage"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/filesync"
	"github.com/moby/buildkit/util/compression"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/grpcerrors"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/moby/buildkit/util/progress"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
)

type ExporterVariant string

const (
	keyImageName        = "name"
	keyLayerCompression = "compression"
	VariantOCI          = "oci"
	VariantDocker       = "docker"
	ociTypes            = "oci-mediatypes"
)

type Opt struct {
	SessionManager *session.Manager
	ImageWriter    *containerimage.ImageWriter
	Variant        ExporterVariant
	LeaseManager   leases.Manager
}

type imageExporter struct {
	opt Opt
}

func New(opt Opt) (exporter.Exporter, error) {
	im := &imageExporter{opt: opt}
	return im, nil
}

func (e *imageExporter) Resolve(ctx context.Context, opt map[string]string) (exporter.ExporterInstance, error) {
	var ot *bool
	i := &imageExporterInstance{
		imageExporter:    e,
		layerCompression: compression.Default,
	}
	for k, v := range opt {
		switch k {
		case keyImageName:
			i.name = v
		case keyLayerCompression:
			switch v {
			case "gzip":
				i.layerCompression = compression.Gzip
			case "uncompressed":
				i.layerCompression = compression.Uncompressed
			default:
				return nil, errors.Errorf("unsupported layer compression type: %v", v)
			}
		case ociTypes:
			ot = new(bool)
			if v == "" {
				*ot = true
				continue
			}
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, errors.Wrapf(err, "non-bool value specified for %s", k)
			}
			*ot = b
		default:
			if i.meta == nil {
				i.meta = make(map[string][]byte)
			}
			i.meta[k] = []byte(v)
		}
	}
	if ot == nil {
		i.ociTypes = e.opt.Variant == VariantOCI
	} else {
		i.ociTypes = *ot
	}
	return i, nil
}

type imageExporterInstance struct {
	*imageExporter
	meta             map[string][]byte
	name             string
	ociTypes         bool
	layerCompression compression.Type
}

func (e *imageExporterInstance) Name() string {
	return "exporting to oci image format"
}

func (e *imageExporterInstance) Export(ctx context.Context, src exporter.Source, sessionID string) (*controlapi.ExporterResponse, error) {
	if e.opt.Variant == VariantDocker && len(src.Refs) > 0 {
		return nil, errors.Errorf("docker exporter does not currently support exporting manifest lists")
	}

	if src.Metadata == nil {
		src.Metadata = make(map[string][]byte)
	}
	for k, v := range e.meta {
		src.Metadata[k] = v
	}

	ctx, done, err := leaseutil.WithLease(ctx, e.opt.LeaseManager, leaseutil.MakeTemporary)
	if err != nil {
		return nil, err
	}
	defer done(context.TODO())

	desc, err := e.opt.ImageWriter.Commit(ctx, src, e.ociTypes, e.layerCompression, sessionID)
	if err != nil {
		return nil, err
	}
	defer func() {
		e.opt.ImageWriter.ContentStore().Delete(context.TODO(), desc.Digest)
	}()
	if desc.Annotations == nil {
		desc.Annotations = map[string]string{}
	}
	desc.Annotations[ocispec.AnnotationCreated] = time.Now().UTC().Format(time.RFC3339)

	resp := make(map[string]string)
	resp["containerimage.digest"] = desc.Digest.String()
	if v, ok := desc.Annotations["config.digest"]; ok {
		resp["containerimage.config.digest"] = v
		delete(desc.Annotations, "config.digeest")
	}

	if n, ok := src.Metadata["image.name"]; e.name == "*" && ok {
		e.name = string(n)
	}

	names, err := normalizedNames(e.name)
	if err != nil {
		return nil, err
	}

	if len(names) != 0 {
		resp["image.name"] = strings.Join(names, ",")
	}

	expOpts := []archiveexporter.ExportOpt{archiveexporter.WithManifest(*desc, names...)}
	switch e.opt.Variant {
	case VariantOCI:
		expOpts = append(expOpts, archiveexporter.WithAllPlatforms(), archiveexporter.WithSkipDockerManifest())
	case VariantDocker:
	default:
		return nil, errors.Errorf("invalid variant %q", e.opt.Variant)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	caller, err := e.opt.SessionManager.Get(timeoutCtx, sessionID, false)
	if err != nil {
		return nil, err
	}

	w, err := filesync.CopyFileWriter(ctx, resp, caller)
	if err != nil {
		return nil, err
	}

	mprovider := contentutil.NewMultiProvider(e.opt.ImageWriter.ContentStore())
	if src.Ref != nil {
		remote, err := src.Ref.GetRemote(ctx, false, e.layerCompression, session.NewGroup(sessionID))
		if err != nil {
			return nil, err
		}
		// unlazy before tar export as the tar writer does not handle
		// layer blobs in parallel (whereas unlazy does)
		if unlazier, ok := remote.Provider.(cache.Unlazier); ok {
			if err := unlazier.Unlazy(ctx); err != nil {
				return nil, err
			}
		}
		for _, desc := range remote.Descriptors {
			mprovider.Add(desc.Digest, remote.Provider)
		}
	}
	if len(src.Refs) > 0 {
		for _, r := range src.Refs {
			remote, err := r.GetRemote(ctx, false, e.layerCompression, session.NewGroup(sessionID))
			if err != nil {
				return nil, err
			}
			if unlazier, ok := remote.Provider.(cache.Unlazier); ok {
				if err := unlazier.Unlazy(ctx); err != nil {
					return nil, err
				}
			}
			for _, desc := range remote.Descriptors {
				mprovider.Add(desc.Digest, remote.Provider)
			}
		}
	}

	response := &controlapi.ExporterResponse{
		ExporterResponse: nil,
	}
	report := oneOffProgress(ctx, "sending tarball")
	if err := archiveexporter.Export(ctx, mprovider, w, expOpts...); err != nil {
		w.Close()
		if grpcerrors.Code(err) == codes.AlreadyExists {
			response.ExporterResponse = resp
			return response, report(nil)
		}
		return nil, report(err)
	}
	err = w.Close()
	if grpcerrors.Code(err) == codes.AlreadyExists {
		response.ExporterResponse = resp
		return response, report(nil)
	}
	response.ExporterResponse = resp
	return response, report(err)
}

func oneOffProgress(ctx context.Context, id string) func(err error) error {
	pw, _, _ := progress.FromContext(ctx)
	now := time.Now()
	st := progress.Status{
		Started: &now,
	}
	pw.Write(id, st)
	return func(err error) error {
		// TODO: set error on status
		now := time.Now()
		st.Completed = &now
		pw.Write(id, st)
		pw.Close()
		return err
	}
}

func normalizedNames(name string) ([]string, error) {
	if name == "" {
		return nil, nil
	}
	names := strings.Split(name, ",")
	var tagNames = make([]string, len(names))
	for i, name := range names {
		parsed, err := reference.ParseNormalizedNamed(name)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse %s", name)
		}
		tagNames[i] = reference.TagNameOnly(parsed).String()
	}
	return tagNames, nil
}
