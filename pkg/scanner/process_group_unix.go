//go:build !windows

package scanner

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the child into its own process group so we can terminate
// the whole tree (nmap/masscan + any children) on cancellation.
func setProcGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func cancelProcessGroup(cmd *exec.Cmd) error {
	return signalProcessGroup(cmd, syscall.SIGTERM)
}

func killProcessGroup(cmd *exec.Cmd) {
	_ = signalProcessGroup(cmd, syscall.SIGKILL)
}

func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}

	// Negative PID signals the process group on Unix.
	err := syscall.Kill(-cmd.Process.Pid, sig)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

