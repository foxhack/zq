// +build !windows

package zeek

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type process struct {
	cmd       *exec.Cmd
	stderrBuf *bytes.Buffer
}

func newProcess(ctx context.Context, pcap io.Reader, zeekpath, outdir string) *process {
	cmd := exec.CommandContext(ctx, zeekpath, "-C", "-r", "-", "--exec", ExecScript, "local")
	cmd.Dir = outdir
	cmd.Stdin = pcap
	p := &process{cmd: cmd, stderrBuf: bytes.NewBuffer(nil)}
	// Capture stderr for error reporting.
	cmd.Stderr = p.stderrBuf
	return p
}

func (p *process) wrapError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr := p.stderrBuf.String()
		stderr = strings.TrimSpace(stderr)
		return fmt.Errorf("zeek exited with status %d: %s", exitErr.ExitCode(), stderr)
	}
	return err
}

func (p *process) start() error {
	return p.wrapError(p.cmd.Start())
}

func (p *process) Wait() error {
	return p.wrapError(p.cmd.Wait())
}
