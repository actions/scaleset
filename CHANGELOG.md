# Changelog

All notable changes to ci-dispatcher are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
and follows the [Conventional Commits](https://www.conventionalcommits.org) spec.

## [0.1.4] - 2026-11-15

### Bug Fixes

- *(agent)* Reap orphaned job processes as PID 1 of the runner container (#12)


## [0.1.3] - 2026-11-14

### CI

- Release on merge, deliver through an acceptance candidate (#10)


## [0.1.2] - 2026-11-13

### Bug Fixes

- *(dispatcher)* Recreate a scale set deleted under its session; one repository's error no longer stops every queue (#9)


### CI

- Publish a release tag without rerunning the checks of main (#6)

- Harden the release check of a tag (#7)


## [0.1.1] - 2026-11-12

### Bug Fixes

- *(chart)* Let the dispatcher read its GitHub secret (#5)


## [0.1.0] - 2026-11-12

### Features

- Add ListRunnerScaleSets on Client (#92)

- Pluggable JWT signing for GitHub App auth (KMS/HSM support) (#117)

- Service ci-dispatcher v0.1 (#3)



