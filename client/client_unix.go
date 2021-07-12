// +build !windows

package client

import (
	"context"
	"net"
	"strings"

	"github.com/moby/buildkit/client/connhelper"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

func defaultConnhelper() connhelper.ConnectionHelper {
	return &platformConnhelper{}
}

type platformConnhelper struct{}

func (c *platformConnhelper) ContextDialer(ctx context.Context, address string) (net.Conn, error) {
	addrParts := strings.SplitN(address, "://", 2)
	if len(addrParts) != 2 {
		return nil, errors.Errorf("invalid address %s", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, addrParts[0], addrParts[1])
}

func (c *platformConnhelper) DialOptions(addr string) ([]grpc.DialOption, error) {
	return nil, nil
}
