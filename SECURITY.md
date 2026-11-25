# Security policy

## What to report privately

Report a vulnerability in NAV itself privately, for example:

- code execution or memory corruption from a crafted file NAV scans
- a crash, hang or runaway memory use on crafted input
- privilege escalation through `navctl service install` or the root LaunchDaemon it creates
- NAV reading, writing or following paths outside what it was asked to scan

A missed detection or a false positive is not a vulnerability. Report those in a
[public issue](https://github.com/yatt-ze/Not-An-Anti-Virus/issues/new), as the
README describes.

## How to report

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/yatt-ze/Not-An-Anti-Virus/security/advisories/new).
Include the NAV version (`navctl --version`), your macOS version, and steps or a
file that reproduce the problem. Never attach live malware; share its SHA-256
hash instead.

## Supported versions

NAV is pre-1.0. Fixes land on `main` and ship in the next release; older
releases are not patched.
