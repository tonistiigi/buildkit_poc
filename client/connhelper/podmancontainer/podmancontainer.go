// Package podmancontainer provides connhelper for podman-container://<container>
package podmancontainer

import (
	"context"
	"net"
	"net/url"

	"github.com/docker/cli/cli/connhelper/commandconn"
	"github.com/moby/buildkit/client/connhelper"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

func init() {
	connhelper.Register("podman-container", Helper)
}

// Helper returns helper for connecting to a Podman container.
// Requires BuildKit v0.5.0 or later in the container.
func Helper(u *url.URL) (connhelper.ConnectionHelper, error) {
	sp, err := SpecFromURL(u)
	if err != nil {
		return nil, err
	}
	return &podmanHelper{sp}, nil
}

type podmanHelper struct {
	sp *Spec
}

func (c *podmanHelper) ContextDialer(ctx context.Context, addr string) (net.Conn, error) {
	// using background context because context remains active for the duration of the process, after dial has completed
	return commandconn.New(context.Background(), "podman", "exec", "-i", c.sp.Container, "buildctl", "dial-stdio")
}

func (c *podmanHelper) DialOptions(addr string) ([]grpc.DialOption, error) {
	return nil, nil
}

// Spec
type Spec struct {
	Container string
}

// SpecFromURL creates Spec from URL.
// URL is like podman-container://<container>
// The <container> part is mandatory.
func SpecFromURL(u *url.URL) (*Spec, error) {
	sp := Spec{
		Container: u.Hostname(),
	}
	if sp.Container == "" {
		return nil, errors.New("url lacks container name")
	}
	return &sp, nil
}
