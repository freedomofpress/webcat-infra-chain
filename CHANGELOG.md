# Unreleased

Nothing yet!

# Version 0.3.2 (2026-02-08)

* feat: add root route to felidae query, #100
* fix: make admin timeouts flexible, #94
* fix: update enrollment structure, #98
* build: declare AGPL license throughout, #95

# Version 0.3.1 (2026-02-03)

* fix: felidae logs info level by default, #89
* build: retool container images via nix build, #86, #91
* build: adds container image for "whiskers" frontend, #86
* docs: bump cometbft to 0.38.x in onboarding guide, #87
* refactor: felidae query shoudl take url once, 88
* test: add felidae-deployer integration test harness, #78

# Version 0.3.0 (2026-01-27)

* feat: migrate to CometBFT v0.38.21, #64

# Version 0.2.1 (2026-01-27)

* feat: add enrollment frontend, #61
* feat: add felidae query subcommand, #80
* fix: config updates should error out, #75
* docs: add network creation steps, #67
* refactor: use bind addresses for cli #77
* build: add nix flake, #71

# Version 0.2.0 (2026-01-07)

* fix: restrict subdomain check to committed domains, #58
* docs: update developer dependencies in README
* feat: add oracle HTTP API, #59
* feat: make timeout configurable

# Version 0.1.1 (2025-11-26)

* fix: json canonicalization should match webext, #49

# Version 0.1.0 (2025-11-26)
* fix: add validation of fields in Enrollment file, #47
* feat: enable initial config to be passed in config file
