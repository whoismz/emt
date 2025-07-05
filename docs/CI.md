# Project CI Documentation

see [CI config](../.gitlab-ci.yml)

Here are two runners for different stages:

1. Build Runner without privileges
2. Test Runner with privileges (Not used for now)

## Current Status

The CI pipeline is now fully operational for build stage and all unit tests.

But for integration test, I ran into a major issue: when I run my program or use `bpftrace` inside docker, it always traces host processes instead of processes inside the container. This causes my integration test to fail.

On my local Docker setup, I found a workaround by adding the `--pid=host` flag to let the container share the host’s process namespace. But GitLab Runner currently doesn’t support this option, as noted in this issue: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/36847
