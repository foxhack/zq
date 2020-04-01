package zeek

import (
	"context"
	"io"
	"log"
	"os/exec"
	"syscall"

	"go.uber.org/zap"
)

var (
	libkernel32              = syscall.MustLoadDLL("kernel32")
	generateConsoleCtrlEvent = libkernel32.MustFindProc("GenerateConsoleCtrlEvent")
)

const (
	createNewProcessGroupFlag = 0x00000200
)

type winproc struct {
	ctx      context.Context
	cmd      *exec.Cmd
	waitDone chan struct{}
	log      *zap.Logger
}

func (w *winproc) start() error {
	err := w.cmd.Start()
	if err != nil {
		w.log.Error("winproc start failed", zap.Error(err))
		return err
	}

	w.waitDone = make(chan struct{})
	go func() {
		select {
		case <-w.ctx.Done():
			w.stop()
		case <-w.waitDone:
		}
	}()

	return nil
}

func (w *winproc) stop() {
	log.Println("winproc stop", w.cmd.Process.Pid)
	// see Call doc for error interpretation.
	r1, _, err := generateConsoleCtrlEvent.Call(syscall.CTRL_BREAK_EVENT, uintptr(w.cmd.Process.Pid))
	if r1 == 0 {
		log.Println("winproc generateConsoleCtrlEvent failed", zap.Error(err))
	}
}

func (w *winproc) Wait() error {
	err := w.cmd.Wait()
	close(w.waitDone)
	return err
}

func newProcess(ctx context.Context, pcap io.Reader, zeekpath, outdir string) *winproc {
	log.Println("alfred: winproc newProcess")
	cmd := exec.Command(zeekpath, "-C", "-r", "-", "--exec", ExecScript, "local")
	cmd.Dir = outdir
	cmd.Stdin = pcap
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_UNICODE_ENVIRONMENT | createNewProcessGroupFlag,
	}
	return &winproc{
		ctx: ctx,
		cmd: cmd,
	}
}
