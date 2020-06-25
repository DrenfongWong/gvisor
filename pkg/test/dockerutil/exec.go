// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dockerutil

import (
	"bytes"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/stdcopy"
)

// ExecOpts hold arguments for Exec calls.
type ExecOpts struct {
	// Env are additional environment variables.
	Env []string

	// Privileged enables privileged mode.
	Privileged bool

	// User is the user to use.
	User string

	// Enables Tty and stdin for the created process.
	UseTty bool

	// WorkDir is the working directory of the process.
	WorkDir string
}

// Exec creates a process inside the container.
func (c *Container) Exec(opts ExecOpts, args ...string) (string, error) {
	p, err := c.doExec(opts, args)
	if err != nil {
		return "", err
	}

	if exitStatus, err := p.WaitExitStatus(); err != nil {
		return "", err
	} else if exitStatus != 0 {
		out, _ := p.Logs()
		return out, fmt.Errorf("process terminated with status: %d", exitStatus)
	}

	return p.Logs()
}

// ExecProcess creates a process inside the container and returns a process struct
// for the caller to use.
func (c *Container) ExecProcess(opts ExecOpts, args ...string) (Process, error) {
	return c.doExec(opts, args)
}

func (c *Container) doExec(r ExecOpts, args []string) (Process, error) {
	config := c.execConfig(r, args)
	resp, err := c.client.ContainerExecCreate(c.ctx, c.id, config)
	if err != nil {
		return Process{}, fmt.Errorf("exec create failed with err: %v", err)
	}

	hijack, err := c.client.ContainerExecAttach(c.ctx, resp.ID, types.ExecStartCheck{})
	if err != nil {
		return Process{}, fmt.Errorf("exec attach failed with err: %v", err)
	}

	if err := c.client.ContainerExecStart(c.ctx, resp.ID, types.ExecStartCheck{}); err != nil {
		hijack.Close()
		return Process{}, fmt.Errorf("exec start failed with err: %v", err)
	}

	return Process{
		container: c,
		execid:    resp.ID,
		conn:      hijack,
	}, nil

}

func (c *Container) execConfig(r ExecOpts, cmd []string) types.ExecConfig {
	env := append(r.Env, fmt.Sprintf(""))
	return types.ExecConfig{
		AttachStdin:  r.UseTty,
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmd,
		Privileged:   r.Privileged,
		WorkingDir:   r.WorkDir,
		Env:          env,
		Tty:          r.UseTty,
		User:         r.User,
	}

}

// Process represents a containerized process.
type Process struct {
	container *Container
	execid    string
	conn      types.HijackedResponse
}

// Write writes buf to the process's stdin.
func (p *Process) Write(timeout time.Duration, buf []byte) (int, error) {
	p.conn.Conn.SetDeadline(time.Now().Add(timeout))
	return p.conn.Conn.Write(buf)
}

// Read returns process's stdout and stderr.
func (p *Process) Read() (string, string, error) {
	var stdout, stderr bytes.Buffer
	if err := p.read(&stdout, &stderr); err != nil {
		return "", "", err
	}
	return stdout.String(), stderr.String(), nil
}

// Logs returns combined stdout/stderr from the process.
func (p *Process) Logs() (string, error) {
	var out bytes.Buffer
	if err := p.read(&out, &out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (p *Process) read(stdout, stderr *bytes.Buffer) error {
	if _, err := stdcopy.StdCopy(stdout, stderr, p.conn.Reader); err != nil {
		return err
	}
	return nil
}

// ExitCode returns the process's exit code.
func (p *Process) ExitCode() (int, error) {
	result, err := p.container.client.ContainerExecInspect(p.container.ctx, p.execid)
	return result.ExitCode, err
}

// IsRunning checks if the process is running.
func (p *Process) IsRunning() (bool, error) {
	result, err := p.container.client.ContainerExecInspect(p.container.ctx, p.execid)
	return result.Running, err

}

// WaitExitStatus until process completes and returns exit status.
func (p *Process) WaitExitStatus() (int, error) {
	waitChan := make(chan (int))
	errChan := make(chan (error))

	go func() {
		for {
			status, err := p.container.client.ContainerExecInspect(p.container.ctx, p.execid)
			if err != nil {
				errChan <- fmt.Errorf("error waiting process %s: continer %v", p.execid, p.container.Name)
			}
			if !status.Running {
				waitChan <- status.ExitCode
			}
			time.Sleep(time.Millisecond * 500)
		}
	}()

	select {
	case ws := <-waitChan:
		return ws, nil
	case err := <-errChan:
		return -1, err
	}
}
