"""Run one agent instance in a fresh, throwaway OpenCode container.

One call = one container: it is created, runs the agent on the mounted
workspace, and is auto-removed (`docker run --rm`) — the "destroy and recreate
per instance" requirement. Nothing persists in the container; everything the
agent produces is written to the host through the /output bind mount.

Mounts used:
  <workspace mounts>  -> read-only, the material the agent explores (per agent)
  <output_dir>        -> /output (read-write): PROMPT.txt goes IN this way, and
                         answer.txt + the OpenCode transcript come OUT this way
  entrypoint.sh       -> /entrypoint.sh (the in-container runner)
"""
import subprocess
import uuid

import config


def run_agent(workspace_mounts, output_dir, api_key, extra_args=None):
    """Run OpenCode once. `workspace_mounts` is a list of (host, container,
    mode) tuples; `output_dir` (host) must already contain PROMPT.txt;
    `extra_args` are extra `docker run` flags (e.g. the network-isolation args
    from network_rules.agent_docker_args()). Returns (exit_code, docker_stdout).
    The agent's answer is left in output_dir/answer.txt by the entrypoint."""
    name = f'agent_{uuid.uuid4().hex[:12]}'
    cmd = ['docker', 'run', '--rm', '--name', name, '--label', config.CONTAINER_LABEL]

    for host, container, mode in workspace_mounts:
        cmd += ['-v', f'{host}:{container}:{mode}']
    cmd += ['-v', f'{output_dir}:/output']
    cmd += ['-v', f'{config.ENTRYPOINT_SH}:/entrypoint.sh:ro']

    # OpenCode reads these from the environment inside the container. The key
    # env var name depends on the provider (config.KEY_ENV).
    cmd += ['-e', f'{config.KEY_ENV}={api_key}']
    cmd += ['-e', f'OPENCODE_MODEL={config.OPENCODE_MODEL}']

    # Custom provider definition (e.g. the Polito LiteLLM endpoint): mount the
    # opencode.json and point OpenCode at it. Built-in providers need none.
    if config.OPENCODE_CONFIG_FILE:
        cmd += ['-v', f'{config.OPENCODE_CONFIG_FILE}:/opencode.json:ro']
        cmd += ['-e', 'OPENCODE_CONFIG=/opencode.json']

    # Network isolation (or anything else the caller wants to add).
    cmd += extra_args or []

    cmd += ['--entrypoint', '/bin/sh', config.DOCKER_IMAGE, '/entrypoint.sh']

    try:
        proc = subprocess.run(cmd, timeout=config.CONTAINER_TIMEOUT,
                              capture_output=True, text=True)
        return proc.returncode, (proc.stdout or '') + (proc.stderr or '')
    except subprocess.TimeoutExpired:
        # The container outlived its budget; make sure it is gone.
        subprocess.run(['docker', 'rm', '-f', name],
                       capture_output=True, text=True)
        return -1, 'ERROR: container timed out'
