// +build gofuzz

package fuzz

import (
	"bytes"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

func Fuzz(data []byte) int {
	_, err := parser.Parse(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	return 1
}
