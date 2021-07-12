package containerimage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/moby/buildkit/util/bklog"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/exporter"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/snapshot"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/util/compression"
	"github.com/moby/buildkit/util/progress"
	"github.com/moby/buildkit/util/system"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type WriterOpt struct {
	Snapshotter  snapshot.Snapshotter
	ContentStore content.Store
	Applier      diff.Applier
	Differ       diff.Comparer
}

func NewImageWriter(opt WriterOpt) (*ImageWriter, error) {
	return &ImageWriter{opt: opt}, nil
}

type ImageWriter struct {
	opt WriterOpt
}

func (ic *ImageWriter) Commit(ctx context.Context, inp exporter.Source, oci bool, compressionType compression.Type, forceCompression bool, sessionID string) (*ocispec.Descriptor, error) {
	platformsBytes, ok := inp.Metadata[exptypes.ExporterPlatformsKey]

	if len(inp.Refs) > 0 && !ok {
		return nil, errors.Errorf("unable to export multiple refs, missing platforms mapping")
	}

	if len(inp.Refs) == 0 {
		remotes, err := ic.exportLayers(ctx, compressionType, forceCompression, session.NewGroup(sessionID), inp.Ref)
		if err != nil {
			return nil, err
		}
		mfstDesc, configDesc, err := ic.commitDistributionManifest(ctx, inp.Ref, inp.Metadata[exptypes.ExporterImageConfigKey], &remotes[0], oci, inp.Metadata[exptypes.ExporterInlineCache])
		if err != nil {
			return nil, err
		}
		if mfstDesc.Annotations == nil {
			mfstDesc.Annotations = make(map[string]string)
		}
		mfstDesc.Annotations["config.digest"] = configDesc.Digest.String()
		return mfstDesc, nil
	}

	var p exptypes.Platforms
	if err := json.Unmarshal(platformsBytes, &p); err != nil {
		return nil, errors.Wrapf(err, "failed to parse platforms passed to exporter")
	}

	if len(p.Platforms) != len(inp.Refs) {
		return nil, errors.Errorf("number of platforms does not match references %d %d", len(p.Platforms), len(inp.Refs))
	}

	refs := make([]cache.ImmutableRef, 0, len(inp.Refs))
	remotesMap := make(map[string]int, len(inp.Refs))
	for id, r := range inp.Refs {
		remotesMap[id] = len(refs)
		refs = append(refs, r)
	}

	remotes, err := ic.exportLayers(ctx, compressionType, forceCompression, session.NewGroup(sessionID), refs...)
	if err != nil {
		return nil, err
	}

	idx := struct {
		// MediaType is reserved in the OCI spec but
		// excluded from go types.
		MediaType string `json:"mediaType,omitempty"`

		ocispec.Index
	}{
		MediaType: ocispec.MediaTypeImageIndex,
		Index: ocispec.Index{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
		},
	}

	if !oci {
		idx.MediaType = images.MediaTypeDockerSchema2ManifestList
	}

	labels := map[string]string{}

	for i, p := range p.Platforms {
		r, ok := inp.Refs[p.ID]
		if !ok {
			return nil, errors.Errorf("failed to find ref for ID %s", p.ID)
		}
		config := inp.Metadata[fmt.Sprintf("%s/%s", exptypes.ExporterImageConfigKey, p.ID)]

		desc, _, err := ic.commitDistributionManifest(ctx, r, config, &remotes[remotesMap[p.ID]], oci, inp.Metadata[fmt.Sprintf("%s/%s", exptypes.ExporterInlineCache, p.ID)])
		if err != nil {
			return nil, err
		}
		dp := p.Platform
		desc.Platform = &dp
		idx.Manifests = append(idx.Manifests, *desc)

		labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = desc.Digest.String()
	}

	idxBytes, err := json.MarshalIndent(idx, "", "   ")
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal index")
	}

	idxDigest := digest.FromBytes(idxBytes)
	idxDesc := ocispec.Descriptor{
		Digest:    idxDigest,
		Size:      int64(len(idxBytes)),
		MediaType: idx.MediaType,
	}
	idxDone := oneOffProgress(ctx, "exporting manifest list "+idxDigest.String())

	if err := content.WriteBlob(ctx, ic.opt.ContentStore, idxDigest.String(), bytes.NewReader(idxBytes), idxDesc, content.WithLabels(labels)); err != nil {
		return nil, idxDone(errors.Wrapf(err, "error writing manifest list blob %s", idxDigest))
	}
	idxDone(nil)

	return &idxDesc, nil
}

func (ic *ImageWriter) exportLayers(ctx context.Context, compressionType compression.Type, forceCompression bool, s session.Group, refs ...cache.ImmutableRef) ([]solver.Remote, error) {
	eg, ctx := errgroup.WithContext(ctx)
	layersDone := oneOffProgress(ctx, "exporting layers")

	out := make([]solver.Remote, len(refs))

	for i, ref := range refs {
		func(i int, ref cache.ImmutableRef) {
			if ref == nil {
				return
			}
			eg.Go(func() error {
				remote, err := ref.GetRemote(ctx, true, compressionType, forceCompression, s)
				if err != nil {
					return err
				}
				out[i] = *remote
				return nil
			})
		}(i, ref)
	}

	if err := layersDone(eg.Wait()); err != nil {
		return nil, err
	}

	return out, nil
}

func (ic *ImageWriter) commitDistributionManifest(ctx context.Context, ref cache.ImmutableRef, config []byte, remote *solver.Remote, oci bool, inlineCache []byte) (*ocispec.Descriptor, *ocispec.Descriptor, error) {
	if len(config) == 0 {
		var err error
		config, err = emptyImageConfig()
		if err != nil {
			return nil, nil, err
		}
	}

	if remote == nil {
		remote = &solver.Remote{
			Provider: ic.opt.ContentStore,
		}
	}

	history, err := parseHistoryFromConfig(config)
	if err != nil {
		return nil, nil, err
	}

	remote, history = normalizeLayersAndHistory(ctx, remote, history, ref, oci)

	config, err = patchImageConfig(config, remote.Descriptors, history, inlineCache)
	if err != nil {
		return nil, nil, err
	}

	var (
		configDigest = digest.FromBytes(config)
		manifestType = ocispec.MediaTypeImageManifest
		configType   = ocispec.MediaTypeImageConfig
	)

	// Use docker media types for older Docker versions and registries
	if !oci {
		manifestType = images.MediaTypeDockerSchema2Manifest
		configType = images.MediaTypeDockerSchema2Config
	}

	mfst := struct {
		// MediaType is reserved in the OCI spec but
		// excluded from go types.
		MediaType string `json:"mediaType,omitempty"`

		ocispec.Manifest
	}{
		MediaType: manifestType,
		Manifest: ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ocispec.Descriptor{
				Digest:    configDigest,
				Size:      int64(len(config)),
				MediaType: configType,
			},
		},
	}

	labels := map[string]string{
		"containerd.io/gc.ref.content.0": configDigest.String(),
	}

	for i, desc := range remote.Descriptors {
		// oci supports annotations but don't export internal annotations
		if oci {
			delete(desc.Annotations, "containerd.io/uncompressed")
			delete(desc.Annotations, "buildkit/createdat")
			for k := range desc.Annotations {
				if strings.HasPrefix(k, "containerd.io/distribution.source.") {
					delete(desc.Annotations, k)
				}
			}
		} else {
			desc.Annotations = nil
		}
		mfst.Layers = append(mfst.Layers, desc)
		labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i+1)] = desc.Digest.String()
	}

	mfstJSON, err := json.MarshalIndent(mfst, "", "   ")
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal manifest")
	}

	mfstDigest := digest.FromBytes(mfstJSON)
	mfstDesc := ocispec.Descriptor{
		Digest: mfstDigest,
		Size:   int64(len(mfstJSON)),
	}
	mfstDone := oneOffProgress(ctx, "exporting manifest "+mfstDigest.String())

	if err := content.WriteBlob(ctx, ic.opt.ContentStore, mfstDigest.String(), bytes.NewReader(mfstJSON), mfstDesc, content.WithLabels((labels))); err != nil {
		return nil, nil, mfstDone(errors.Wrapf(err, "error writing manifest blob %s", mfstDigest))
	}
	mfstDone(nil)

	configDesc := ocispec.Descriptor{
		Digest:    configDigest,
		Size:      int64(len(config)),
		MediaType: configType,
	}
	configDone := oneOffProgress(ctx, "exporting config "+configDigest.String())

	if err := content.WriteBlob(ctx, ic.opt.ContentStore, configDigest.String(), bytes.NewReader(config), configDesc); err != nil {
		return nil, nil, configDone(errors.Wrap(err, "error writing config blob"))
	}
	configDone(nil)

	return &ocispec.Descriptor{
		Digest:    mfstDigest,
		Size:      int64(len(mfstJSON)),
		MediaType: manifestType,
	}, &configDesc, nil
}

func (ic *ImageWriter) ContentStore() content.Store {
	return ic.opt.ContentStore
}

func (ic *ImageWriter) Snapshotter() snapshot.Snapshotter {
	return ic.opt.Snapshotter
}

func (ic *ImageWriter) Applier() diff.Applier {
	return ic.opt.Applier
}

func emptyImageConfig() ([]byte, error) {
	pl := platforms.Normalize(platforms.DefaultSpec())

	type image struct {
		ocispec.Image

		// Variant defines platform variant. To be added to OCI.
		Variant string `json:"variant,omitempty"`
	}

	img := image{
		Image: ocispec.Image{
			Architecture: pl.Architecture,
			OS:           pl.OS,
		},
		Variant: pl.Variant,
	}
	img.RootFS.Type = "layers"
	img.Config.WorkingDir = "/"
	img.Config.Env = []string{"PATH=" + system.DefaultPathEnv(pl.OS)}
	dt, err := json.Marshal(img)
	return dt, errors.Wrap(err, "failed to create empty image config")
}

func parseHistoryFromConfig(dt []byte) ([]ocispec.History, error) {
	var config struct {
		History []ocispec.History
	}
	if err := json.Unmarshal(dt, &config); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal history from config")
	}
	return config.History, nil
}

func patchImageConfig(dt []byte, descs []ocispec.Descriptor, history []ocispec.History, cache []byte) ([]byte, error) {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(dt, &m); err != nil {
		return nil, errors.Wrap(err, "failed to parse image config for patch")
	}

	var rootFS ocispec.RootFS
	rootFS.Type = "layers"
	for _, desc := range descs {
		rootFS.DiffIDs = append(rootFS.DiffIDs, digest.Digest(desc.Annotations["containerd.io/uncompressed"]))
	}
	dt, err := json.Marshal(rootFS)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal rootfs")
	}
	m["rootfs"] = dt

	dt, err = json.Marshal(history)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal history")
	}
	m["history"] = dt

	if _, ok := m["created"]; !ok {
		var tm *time.Time
		for _, h := range history {
			if h.Created != nil {
				tm = h.Created
			}
		}
		dt, err = json.Marshal(&tm)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal creation time")
		}
		m["created"] = dt
	}

	if cache != nil {
		dt, err := json.Marshal(cache)
		if err != nil {
			return nil, err
		}
		m["moby.buildkit.cache.v0"] = dt
	}

	dt, err = json.Marshal(m)
	return dt, errors.Wrap(err, "failed to marshal config after patch")
}

func normalizeLayersAndHistory(ctx context.Context, remote *solver.Remote, history []ocispec.History, ref cache.ImmutableRef, oci bool) (*solver.Remote, []ocispec.History) {
	refMeta := getRefMetadata(ref, len(remote.Descriptors))

	var historyLayers int
	for _, h := range history {
		if !h.EmptyLayer {
			historyLayers++
		}
	}

	if historyLayers > len(remote.Descriptors) {
		// this case shouldn't happen but if it does force set history layers empty
		// from the bottom
		bklog.G(ctx).Warn("invalid image config with unaccounted layers")
		historyCopy := make([]ocispec.History, 0, len(history))
		var l int
		for _, h := range history {
			if l >= len(remote.Descriptors) {
				h.EmptyLayer = true
			}
			if !h.EmptyLayer {
				l++
			}
			historyCopy = append(historyCopy, h)
		}
		history = historyCopy
	}

	if len(remote.Descriptors) > historyLayers {
		// some history items are missing. add them based on the ref metadata
		for _, md := range refMeta[historyLayers:] {
			history = append(history, ocispec.History{
				Created:   md.createdAt,
				CreatedBy: md.description,
				Comment:   "buildkit.exporter.image.v0",
			})
		}
	}

	var layerIndex int
	for i, h := range history {
		if !h.EmptyLayer {
			if remote.Descriptors[layerIndex].Digest == exptypes.EmptyGZLayer {
				h.EmptyLayer = true
				remote.Descriptors = append(remote.Descriptors[:layerIndex], remote.Descriptors[layerIndex+1:]...)
			} else {
				if h.Created == nil {
					h.Created = refMeta[layerIndex].createdAt
				}
				layerIndex++
			}
		}
		history[i] = h
	}

	// Find the first new layer time. Otherwise, the history item for a first
	// metadata command would be the creation time of a base image layer.
	// If there is no such then the last layer with timestamp.
	var created *time.Time
	var noCreatedTime bool
	for _, h := range history {
		if h.Created != nil {
			created = h.Created
			if noCreatedTime {
				break
			}
		} else {
			noCreatedTime = true
		}
	}

	// Fill in created times for all history items to be either the first new
	// layer time or the previous layer.
	noCreatedTime = false
	for i, h := range history {
		if h.Created != nil {
			if noCreatedTime {
				created = h.Created
			}
		} else {
			noCreatedTime = true
			h.Created = created
		}
		history[i] = h
	}

	// convert between oci and docker media types (or vice versa) if needed
	remote.Descriptors = compression.ConvertAllLayerMediaTypes(oci, remote.Descriptors...)

	return remote, history
}

type refMetadata struct {
	description string
	createdAt   *time.Time
}

func getRefMetadata(ref cache.ImmutableRef, limit int) []refMetadata {
	if limit <= 0 {
		return nil
	}
	now := time.Now()
	meta := refMetadata{
		description: "created by buildkit", // shouldn't be shown but don't fail build
		createdAt:   &now,
	}
	if ref == nil {
		return append(getRefMetadata(nil, limit-1), meta)
	}
	if descr := cache.GetDescription(ref.Metadata()); descr != "" {
		meta.description = descr
	}
	createdAt := cache.GetCreatedAt(ref.Metadata())
	meta.createdAt = &createdAt
	p := ref.Parent()
	if p != nil {
		defer p.Release(context.TODO())
	}
	return append(getRefMetadata(p, limit-1), meta)
}

func oneOffProgress(ctx context.Context, id string) func(err error) error {
	pw, _, _ := progress.NewFromContext(ctx)
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
