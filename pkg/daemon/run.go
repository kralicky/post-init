package daemon

import (
	"bytes"
	"os"
	"os/exec"

	"github.com/kralicky/post-init/pkg/api"
)

func RunCommand(cmd *api.Command) (*api.CommandOutput, error) {
	c := exec.Command(cmd.Command, cmd.Args...)
	c.Env = append(os.Environ(), cmd.Env...)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	c.Stdin = nil
	c.Stdout = stdoutBuf
	c.Stderr = stderrBuf
	err := c.Run()
	if err != nil {
		// Do not treat non-zero return code (ExitError) as an error here
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, err
		}
	}
	return &api.CommandOutput{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: int32(c.ProcessState.ExitCode()),
	}, nil
}

func RunScript(cmd *api.Script) (*api.ScriptOutput, error) {
	// Write a temporary file with the script
	f, err := os.CreateTemp("", "post-init-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(cmd.Script)
	if err != nil {
		return nil, err
	}
	f.Close()

	c := exec.Command(cmd.Interpreter, append([]string{f.Name()}, cmd.Args...)...)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	c.Stdin = nil
	c.Stdout = stdoutBuf
	c.Stderr = stderrBuf
	err = c.Run()
	if err != nil {
		// Do not treat non-zero return code (ExitError) as an error here
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, err
		}
	}
	return &api.ScriptOutput{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: int32(c.ProcessState.ExitCode()),
	}, nil
}
