package worker

import (
	"context"

	"github.com/containerd/containerd/filters"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/worker/workercontext"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Controller holds worker instances.
// Currently, only local workers are supported.
type Controller struct {
	// TODO: define worker interface and support remote ones
	workers []Worker
}

// Add adds a local worker.
// The first worker becomes the default.
//
// Add is not thread-safe.
func (c *Controller) Add(w Worker) error {
	c.workers = append(c.workers, w)
	return nil
}

// List lists workers
func (c *Controller) List(filterStrings ...string) ([]Worker, error) {
	filter, err := filters.ParseAll(filterStrings...)
	if err != nil {
		return nil, err
	}
	var workers []Worker
	for _, w := range c.workers {
		if filter.Match(adaptWorker(w)) {
			workers = append(workers, w)
		}
	}
	return workers, nil
}

// GetDefault returns the default local worker
func (c *Controller) GetDefault() (Worker, error) {
	if len(c.workers) == 0 {
		return nil, errors.Errorf("no default worker")
	}
	return c.workers[0], nil
}

func (c *Controller) Get(id string) (Worker, error) {
	for _, w := range c.workers {
		if w.ID() == id {
			return w, nil
		}
	}
	return nil, errors.Errorf("worker %s not found", id)
}

func (c *Controller) GetFromContext(ctx context.Context) (Worker, error) {
	if selector := workercontext.Worker(ctx); selector != "" {
		logrus.Debugf("worker selector %q is specified via context", selector)
		workers, err := c.List()
		if err != nil {
			return nil, nil
		}
		for _, w := range workers {
			id := w.ID()
			if selector == id {
				logrus.Debugf("worker selector %q matches ID %q", selector, id)
				return w, nil
			}
			executorName := w.Labels()[LabelExecutor]
			if selector == executorName {
				logrus.Debugf("worker selector %q matches ID %q (%q=%q)", selector, id,
					LabelExecutor, executorName)
				return w, nil
			}
		}
		return nil, errors.Errorf("invalid worker selector %q", selector)
	}
	logrus.Debug("no worker was specified via context")
	// Hint for debugging: Add panic() here to verify that the worker ID is passed to every ctx.
	return c.GetDefault()
}

// TODO: add Get(Constraint) (*Worker, error)

// WorkerInfos returns slice of WorkerInfo.
// The first item is the default worker.
func (c *Controller) WorkerInfos() []client.WorkerInfo {
	out := make([]client.WorkerInfo, 0, len(c.workers))
	for _, w := range c.workers {
		out = append(out, client.WorkerInfo{
			ID:        w.ID(),
			Labels:    w.Labels(),
			Platforms: w.Platforms(true),
		})
	}
	return out
}
