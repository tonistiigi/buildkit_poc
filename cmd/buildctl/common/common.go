package common

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/tracing/detect"
	"github.com/moby/buildkit/worker/workercontext"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
	"go.opentelemetry.io/otel/trace"
)

// ResolveClient resolves a client from CLI args
func ResolveClient(c *cli.Context) (*client.Client, error) {
	serverName := c.GlobalString("tlsservername")
	if serverName == "" {
		// guess servername as hostname of target address
		uri, err := url.Parse(c.GlobalString("addr"))
		if err != nil {
			return nil, err
		}
		serverName = uri.Hostname()
	}

	var caCert string
	var cert string
	var key string

	tlsDir := c.GlobalString("tlsdir")

	if tlsDir != "" {
		// Look for ca.pem and, if it exists, set caCert to that
		// Look for cert.pem and, if it exists, set key to that
		// Look for key.pem and, if it exists, set tlsDir to that
		for _, v := range [3]string{"ca.pem", "cert.pem", "key.pem"} {
			file := filepath.Join(tlsDir, v)
			if _, err := os.Stat(file); err == nil {
				switch v {
				case "ca.pem":
					caCert = file
				case "cert.pem":
					cert = file
				case "key.pem":
					key = file
				}
			} else {
				return nil, err
			}
		}

		if c.GlobalString("tlscacert") != "" || c.GlobalString("tlscert") != "" || c.GlobalString("tlskey") != "" {
			return nil, errors.New("cannot specify tlsdir and tlscacert/tlscert/tlskey at the same time")
		}
	} else {
		caCert = c.GlobalString("tlscacert")
		cert = c.GlobalString("tlscert")
		key = c.GlobalString("tlskey")
	}

	opts := []client.ClientOpt{client.WithFailFast()}

	ctx := CommandContext(c)

	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		opts = append(opts, client.WithTracerProvider(span.TracerProvider()))

		exp, err := detect.Exporter()
		if err != nil {
			return nil, err
		}

		if td, ok := exp.(client.TracerDelegate); ok {
			opts = append(opts, client.WithTracerDelegate(td))
		}
	}

	if caCert != "" || cert != "" || key != "" {
		opts = append(opts, client.WithCredentials(serverName, caCert, cert, key))
	}

	timeout := time.Duration(c.GlobalInt("timeout"))
	ctx, cancel := context.WithTimeout(ctx, timeout*time.Second)
	defer cancel()

	if worker := c.GlobalString("worker"); worker != "" {
		ctx = workercontext.WithWorker(ctx, worker)
	}

	return client.New(ctx, c.GlobalString("addr"), opts...)
}
