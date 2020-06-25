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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Container contains the Name and Runtime of the container.
type Container struct {
	ctx      context.Context
	logger   testutil.Logger
	Runtime  string
	Name     string
	client   *client.Client
	id       string
	mounts   []mount.Mount
	links    []string
	cleanups []func()
	copyErr  error
}

// Mount describes a mount point inside the container.
type Mount struct {
	// Source is the path outside the container.
	Source string

	// Target is the path inside the container.
	Target string

	// Mode tells whether the mount inside the container should be readonly.
	Mode MountMode
}

// Link informs dockers that a given container needs to be made accessible from
// the container being configured.
type Link struct {
	// Source is the container to connect to.
	Source *Docker

	// CSource is the container to connect to.
	CSource *Container

	// Target is the alias for the container.
	Target string
}

// RunOpts are options for running a container.
type RunOpts struct {
	// Image is the image relative to images/. This will be mangled
	// appropriately, to ensure that only first-party images are used.
	Image string

	// Memory is the memory limit in kB.
	Memory int

	// Cpus in which to allow execution. ("0", "1", "0-2").
	CpusetCpus string

	// Ports are the ports to be allocated.
	Ports []int

	// WorkDir sets the working directory.
	WorkDir string

	// ReadOnly sets the read-only flag.
	ReadOnly bool

	// Env are additional environment variables.
	Env []string

	// User is the user to use.
	User string

	// Privileged enables privileged mode.
	Privileged bool

	// CapAdd are the extra set of capabilities to add.
	CapAdd []string

	// CapDrop are the extra set of capabilities to drop.
	CapDrop []string

	// Pty indicates that a pty will be allocated. If this is non-nil, then
	// this will run after start-up with the *exec.Command and Pty file
	// passed in to the function.
	Pty func(*exec.Cmd, *os.File)

	// Foreground indicates that the container should be run in the
	// foreground. If this is true, then the output will be available as a
	// return value from the Run function.
	Foreground bool

	// Mounts is the list of directories/files to be mounted inside the container.
	Mounts []Mount

	// Links is the list of containers to be connected to the container.
	Links []Link

	// Extra are extra arguments that may be passed.
	Extra []string

	// Sets the container to autoremove (e.g. --rm flag).
	AutoRemove bool
}

// MakeContainer sets up the struct for a Docker container.
//
// Names of containers will be unique.
func MakeContainer(logger testutil.Logger) *Container {
	// Slashes are not allowed in container names.
	name := testutil.RandomID(logger.Name())
	name = strings.ReplaceAll(name, "/", "-")
	ctx := context.Background()

	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil
	}

	client.NegotiateAPIVersion(ctx)

	return &Container{
		ctx:     ctx,
		logger:  logger,
		Name:    name,
		Runtime: *runtime,
		client:  client,
	}
}

// Spawn starts the container and detaches.
func (c *Container) Spawn(r RunOpts, args ...string) error {
	if err := c.create(r, args); err != nil {
		return err
	}

	return c.Start()
}

// Run is analogous to 'docker run'.
func (c *Container) Run(r RunOpts, args ...string) (string, error) {
	if err := c.create(r, args); err != nil {
		return "", err
	}

	if err := c.Start(); err != nil {
		return "", err
	}

	if err := c.Wait(); err != nil {
		return "", err
	}

	return c.Logs()
}

// Create is analogous to 'docker create'.
func (c *Container) Create(r RunOpts, args ...string) error {
	return c.create(r, args)
}

func (c *Container) create(r RunOpts, args []string) error {
	conf := c.config(r, args)
	host := c.hostConfig(r)
	cont, err := c.client.ContainerCreate(c.ctx, conf, host, nil, c.Name)
	if err != nil {
		return err
	}
	c.id = cont.ID
	return nil
}

func (c *Container) config(r RunOpts, args []string) *container.Config {
	ports := nat.PortSet{}
	for _, p := range r.Ports {
		port := nat.Port(fmt.Sprintf("%d", p))
		ports[port] = struct{}{}
	}
	env := append(r.Env, fmt.Sprintf("RUNSC_TEST_NAME=%s", c.Name))

	return &container.Config{
		Image:        testutil.ImageByName(r.Image),
		Cmd:          args,
		ExposedPorts: ports,
		Env:          env,
		WorkingDir:   r.WorkDir,
		User:         r.User,
	}
}

func (c *Container) hostConfig(r RunOpts) *container.HostConfig {

	// Make the mounts.
	for _, m := range r.Mounts {
		c.mounts = append(c.mounts, mount.Mount{
			Type:     mount.TypeBind,
			Target:   m.Target,
			Source:   m.Source,
			ReadOnly: m.Mode == ReadOnly,
		})
	}

	// Make the links.
	for _, l := range r.Links {
		c.links = append(c.links, fmt.Sprintf("%s:%s", l.CSource.Name, l.Target))
	}

	return &container.HostConfig{
		Runtime:         c.Runtime,
		Mounts:          c.mounts,
		PublishAllPorts: true,
		Links:           c.links,
		CapAdd:          r.CapAdd,
		CapDrop:         r.CapDrop,
		Privileged:      r.Privileged,
		ReadonlyRootfs:  r.ReadOnly,
		Resources: container.Resources{
			Memory:     int64(r.Memory), // In bytes.
			CpusetCpus: r.CpusetCpus,
		},
		AutoRemove: r.AutoRemove,
	}
}

// Start starts the container.
func (c *Container) Start() error {
	return c.client.ContainerStart(c.ctx, c.id, types.ContainerStartOptions{})
}

// Stop stops the container.
func (c *Container) Stop() error {
	return c.client.ContainerStop(c.ctx, c.id, nil)
}

// Pause calls 'docker pause'.
func (c *Container) Pause() error {
	return c.client.ContainerPause(c.ctx, c.id)
}

// Unpause calls 'docker unpause'.
func (c *Container) Unpause() error {
	return c.client.ContainerUnpause(c.ctx, c.id)
}

// Checkpoint calls 'docker checkpoint'.
func (c *Container) Checkpoint(name string) error {
	return c.client.CheckpointCreate(c.ctx, c.Name, types.CheckpointCreateOptions{CheckpointID: name, Exit: true})
}

// Restore calls 'docker start --checkname [name]'.
func (c *Container) Restore(name string) error {
	return c.client.ContainerStart(c.ctx, c.id, types.ContainerStartOptions{CheckpointID: name})
}

// Logs calls 'docker logs'.
func (c *Container) Logs() (string, error) {
	var out bytes.Buffer
	err := c.logs(&out, &out)
	return out.String(), err
}

func (c *Container) logs(stdout, stderr *bytes.Buffer) error {
	opts := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
	writer, err := c.client.ContainerLogs(c.ctx, c.id, opts)
	if err != nil {
		return err
	}
	defer writer.Close()
	_, err = stdcopy.StdCopy(stdout, stderr, writer)

	return err
}

// FindIP returns the IP address of the container.
func (c *Container) FindIP() (net.IP, error) {
	resp, err := c.client.ContainerInspect(c.ctx, c.id)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(resp.NetworkSettings.DefaultNetworkSettings.IPAddress)
	if ip == nil {
		return net.IP{}, fmt.Errorf("invalid IP: %q", ip)
	}
	return ip, nil
}

// FindPort returns the host port that is mapped to 'sandboxPort'. This calls
// docker to allocate a free port in the host and prevent conflicts.
func (c *Container) FindPort(sandboxPort int) (int, error) {
	desc, err := c.client.ContainerInspect(c.ctx, c.id)
	if err != nil {
		return -1, fmt.Errorf("error retreiving port: %v", err)
	}

	format := fmt.Sprintf("%d/tcp", sandboxPort)
	ports, ok := desc.NetworkSettings.Ports[nat.Port(format)]
	if !ok {
		return -1, fmt.Errorf("error retrieving port: %v", err)

	}

	port, err := strconv.Atoi(ports[0].HostPort)
	if err != nil {
		return -1, fmt.Errorf("error parsing port %q: %v", port, err)
	}
	return port, nil
}

// CopyFiles copies in and mounts the given files. They are always ReadOnly.
func (c *Container) CopyFiles(opts *RunOpts, target string, sources ...string) {
	dir, err := ioutil.TempDir("", c.Name)
	if err != nil {
		c.copyErr = fmt.Errorf("ioutil.TempDir failed: %v", err)
		return
	}
	c.cleanups = append(c.cleanups, func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		c.copyErr = fmt.Errorf("os.Chmod(%q, 0755) failed: %v", dir, err)
		return
	}
	for _, name := range sources {
		src, err := testutil.FindFile(name)
		if err != nil {
			c.copyErr = fmt.Errorf("testutil.FindFile(%q) failed: %v", name, err)
			return
		}
		dst := path.Join(dir, path.Base(name))
		if err := testutil.Copy(src, dst); err != nil {
			c.copyErr = fmt.Errorf("testutil.Copy(%q, %q) failed: %v", src, dst, err)
			return
		}
		c.logger.Logf("copy: %s -> %s", src, dst)
	}
	opts.Mounts = append(opts.Mounts, Mount{
		Source: dir,
		Target: target,
		Mode:   ReadOnly,
	})
}

// Status inspects the container returns its status.
func (c *Container) Status() (types.ContainerState, error) {
	resp, err := c.client.ContainerInspect(c.ctx, c.id)
	return *resp.State, err
}

// Wait waits for the container to exit.
func (c *Container) Wait() error {
	statusChan, errChan := c.client.ContainerWait(c.ctx, c.id, container.WaitConditionNotRunning)
	select {
	case err := <-errChan:
		return err
	case <-statusChan:
		return nil
	}
}

// WaitTimeout waits for the container to exit.
func (c *Container) WaitTimeout(timeout time.Duration) error {
	timeoutChan := time.After(timeout)
	statusChan, errChan := c.client.ContainerWait(c.ctx, c.id, container.WaitConditionNotRunning)
	select {
	case err := <-errChan:
		return err
	case <-statusChan:
		return nil
	case <-timeoutChan:
		return fmt.Errorf("container %s timed out after %v seconds", c.Name, timeout.Seconds())
	}
}

// WaitForOutput calls 'docker logs' to retrieve containers output and searches
// for the given pattern.
func (c *Container) WaitForOutput(pattern string, timeout time.Duration) (string, error) {
	matches, err := c.WaitForOutputSubmatch(pattern, timeout)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", nil
	}
	return matches[0], nil
}

// WaitForOutputSubmatch calls 'docker logs' to retrieve containers output and
// searches for the given pattern. It returns any regexp submatches as well.
func (c *Container) WaitForOutputSubmatch(pattern string, timeout time.Duration) ([]string, error) {
	re := regexp.MustCompile(pattern)

	var stdout, stderr string

	for exp := time.Now().Add(timeout); time.Now().Before(exp); {
		out, err := c.Logs()
		if err != nil {
			return nil, err
		}

		if matches := re.FindStringSubmatch(out); matches != nil {
			return matches, nil
		}

		state, err := c.client.ContainerInspect(c.ctx, c.id)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect container %s: %v", c.Name, err)
		}
		if !state.State.Running {
			return nil, fmt.Errorf("no longer running: %v", err)
		}

		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for output %q: stdout: %s, stderr: %s", re.String(), stdout, stderr)
}

// Kill kills the container.
func (c *Container) Kill() error {
	return c.client.ContainerKill(c.ctx, c.id, "")
}

// Remove calls 'docker rm'.
func (c *Container) Remove() error {
	// Remove the image.
	remove := types.ContainerRemoveOptions{
		RemoveVolumes: c.mounts != nil,
		RemoveLinks:   c.links != nil,
		Force:         true,
	}
	return c.client.ContainerRemove(c.ctx, c.Name, remove)
}

// CleanUp kills and deletes the container (best effort).
func (c *Container) CleanUp() {
	// Kill the container.
	if err := c.Kill(); err != nil && strings.Contains(err.Error(), "is not running") {
		// Just log; can't do anything here.
		c.logger.Logf("error killing container %q: %v", c.Name, err)
	}
	// Remove the image.
	if err := c.Remove(); err != nil {
		c.logger.Logf("error removing container %q: %v", c.Name, err)
	}
	// Forget all mounts.
	c.mounts = nil
	// Execute all cleanups.
	for _, c := range c.cleanups {
		c()
	}
	c.cleanups = nil
}
