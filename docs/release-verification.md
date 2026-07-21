# Release verification

This page records observed evidence only. It is not a substitute for running
the checked-in gates on the release commit.

## macOS

Observed locally on macOS with Python 3.14.4, Node.js 22.13.1 and Docker
Desktop on 21 July 2026:

- the focused release gate passed 91 backend scheduler, cleanup, reproduction,
  and recorder tests, 9 frontend fuzzing/reproduction tests, TypeScript checking,
  Python compilation, and the Vite production build;
- one browser-driven real loop independently generated and validated component
  libFuzzer and system AFL++ targets, accumulated exact clean line, function,
  and branch coverage, admitted only first-hit corpus inputs, grouped multiple
  crashes into one reproducible priority-1 true-vulnerability finding, reproduced
  it in the browser terminal, and recovered the manager and running campaigns
  after backend restart;
- that run exposed one final mobile keyboard-accessibility issue. A focused Axe
  check now reports no `scrollable-region-focusable` violation at 390 by 844;
- a second real loop selected an equally valid stdin-based system target and
  exposed a missing browser-reproduction input mode. Exact sealed stdin replay
  is now covered by focused service and named-container tests, with no shell,
  TTY, interactive input, or testcase mount;
- release screenshots were captured for the intro, empty Projects view, and
  evidence-backed desktop Overview.

The final browser-driven rerun after both fixes remains pending because the
Codex desktop execution-approval quota rejected the command before it started.
Do not report the release gate as complete until that exact rerun passes.

## Container platform

All BigEye database, image-build and campaign container paths request
`linux/amd64`. Local image and container architecture inspection remains part
of the final release evidence; it does not prove that the host application runs
on Linux.

## Linux CI

**Pending.** The Ubuntu 24.04 workflow is checked in, but no GitHub-hosted run
has been observed for this local branch. A local macOS host running
`linux/amd64` containers is not reported as Linux-host evidence.
