package ops

import (
	"context"
	"encoding/json"
	"os"

	"github.com/containerd/continuity/fs"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend"
	dockerfile "github.com/moby/buildkit/frontend/dockerfile/builder"
	"github.com/moby/buildkit/frontend/gateway"
	"github.com/moby/buildkit/frontend/gateway/forwarder"
	"github.com/moby/buildkit/snapshot"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/llbsolver"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/worker"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

const buildCacheType = "buildkit.build.v0"

type buildOp struct {
	op        *pb.BuildOp
	llbBridge frontend.FrontendLLBBridge
	v         solver.Vertex
	w         worker.Worker
	wi        frontend.WorkerInfos
}

func NewBuildOp(v solver.Vertex, op *pb.Op_Build, b frontend.FrontendLLBBridge, w worker.Worker, wi frontend.WorkerInfos) (solver.Op, error) {
	if err := llbsolver.ValidateOp(&pb.Op{Op: op}); err != nil {
		return nil, err
	}
	return &buildOp{
		op:        op.Build,
		llbBridge: b,
		v:         v,
		w:         w,
		wi:        wi,
	}, nil
}

func (b *buildOp) CacheMap(ctx context.Context, index int) (*solver.CacheMap, bool, error) {
	dt, err := json.Marshal(struct {
		Type string
		Exec *pb.BuildOp
	}{
		Type: buildCacheType,
		Exec: b.op,
	})
	if err != nil {
		return nil, false, err
	}

	return &solver.CacheMap{
		Digest: digest.FromBytes(dt),
		Deps: make([]struct {
			Selector          digest.Digest
			ComputeDigestFunc solver.ResultBasedCacheFunc
		}, len(b.v.Inputs())),
	}, true, nil
}

func (b *buildOp) Exec(ctx context.Context, inputs []solver.Result) (outputs []solver.Result, retErr error) {
	if b.op.Builder == pb.LLBBuilder {
		return b.buildWithLLB(ctx, inputs)
	}
	switch b.op.Frontend {
	case "gateway.v0":
		return b.buildWithGateway(ctx, inputs)
	case "dockerfile.v0":
		return b.buildWithDockerfile(ctx, inputs)
	default:
		return nil, errors.Errorf("unsupported frontend %q", b.op.Frontend)
	}
}

func (b *buildOp) buildWithLLB(ctx context.Context, inputs []solver.Result) (outputs []solver.Result, retErr error) {
	builderInputs := b.op.Inputs
	llbDef, ok := builderInputs[pb.LLBDefinitionInput]
	if !ok {
		return nil, errors.Errorf("no llb definition input %s found", pb.LLBDefinitionInput)
	}

	i := int(llbDef.Input)
	if i >= len(inputs) {
		return nil, errors.Errorf("invalid index %v", i) // TODO: this should be validated before
	}
	inp := inputs[i]

	ref, ok := inp.Sys().(*worker.WorkerRef)
	if !ok {
		return nil, errors.Errorf("invalid reference for build %T", inp.Sys())
	}

	mount, err := ref.ImmutableRef.Mount(ctx, true)
	if err != nil {
		return nil, err
	}

	lm := snapshot.LocalMounter(mount)

	root, err := lm.Mount()
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil && lm != nil {
			lm.Unmount()
		}
	}()

	fn := pb.LLBDefaultDefinitionFile
	if override, ok := b.op.Attrs[pb.AttrLLBDefinitionFilename]; ok {
		fn = override
	}

	newfn, err := fs.RootPath(root, fn)
	if err != nil {
		return nil, errors.Wrapf(err, "working dir %s points to invalid target", fn)
	}

	f, err := os.Open(newfn)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %s", newfn)
	}

	def, err := llb.ReadFrom(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	lm.Unmount()
	lm = nil

	proxy, err := b.llbBridge.Solve(ctx, frontend.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}

	for _, r := range proxy.Refs {
		r.Release(context.TODO())
	}

	res, err := proxy.Ref.Result(ctx)
	if err != nil {
		return nil, err
	}

	return []solver.Result{res}, err
}

func (b *buildOp) buildWithGateway(ctx context.Context, inputs []solver.Result) (outputs []solver.Result, retErr error) {
	builderInput := inputs[b.op.Builder]

	wref, ok := builderInput.Sys().(*worker.WorkerRef)
	if !ok {
		return nil, errors.Errorf("invalid reference for build %T", builderInput.Sys())
	}
	rootFS := wref.ImmutableRef

	cfg := specs.ImageConfig{
		Entrypoint: b.op.Meta.Args,
		Env:        b.op.Meta.Env,
		WorkingDir: b.op.Meta.Cwd,
	}

	proxy, err := gateway.ExecWithFrontend(ctx, b.llbBridge, b.wi, rootFS, cfg, b.op.Attrs, b.op.Defs)
	if err != nil {
		return nil, err
	}

	for _, r := range proxy.Refs {
		r.Release(context.TODO())
	}

	res, err := proxy.Ref.Result(ctx)
	if err != nil {
		return nil, err
	}

	return []solver.Result{res}, nil
}

func (b *buildOp) buildWithDockerfile(ctx context.Context, inputs []solver.Result) (outputs []solver.Result, retErr error) {
	frontend := forwarder.NewGatewayForwarder(b.wi, dockerfile.Build)
	proxy, err := frontend.Solve(ctx, b.llbBridge, b.op.Attrs, b.op.Defs)
	if err != nil {
		return nil, err
	}

	for _, r := range proxy.Refs {
		r.Release(context.TODO())
	}

	res, err := proxy.Ref.Result(ctx)
	if err != nil {
		return nil, err
	}

	return []solver.Result{res}, nil
}
