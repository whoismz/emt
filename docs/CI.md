# Project CI Documentation

see [CI config](../.gitlab-ci.yml)

Here are two runners for different stages:

1. Build Runner without privileges
2. Test Runner with privileges

### Current Status

CI failing due to `bpf_repeat()` dependency on Linux 6.4+

### TODO

Use Newer kernel in Docker environment
