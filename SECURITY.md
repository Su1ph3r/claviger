# Security Policy

Claviger is a tool for authorized security testing. If you find a vulnerability
in Claviger itself, please report it privately so it can be fixed before it is
made public.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. That opens a private advisory visible
only to the maintainer.

Please include:

- the version or commit you tested (`claviger version`),
- your operating system,
- a description of the issue and its impact,
- steps to reproduce, ideally with a minimal config.

You will get an acknowledgement within a few days. Once a fix is ready, the
advisory is published with credit to you unless you ask to stay anonymous.

## Scope

In scope: the daemon, the gateway, the control socket, the recipes, and the
replay and corpus paths. Out of scope: issues that require an attacker who
already has local access to the operator's account (the control socket and the
loopback gateway ports are owner-trust boundaries by design), and findings in
third-party dependencies (report those upstream).

## Using Claviger safely

Claviger holds live credentials and drives requests at a target. Only point it
at systems you are authorized to test. The gateway binds loopback only and the
control socket is owner-readable; do not expose either on a shared or untrusted
host.
