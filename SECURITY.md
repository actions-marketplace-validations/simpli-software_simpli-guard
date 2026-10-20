# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting:
open the **Security** tab of this repository and choose **Report a vulnerability**. Please do
not open a public issue or pull request for a security problem.

Include what you found, how to reproduce it, and the version or commit you tested.

## What to expect

This project is maintained on a best-effort basis with no SLA. We will read reports and reply
when we can, and we will credit you in the fix if you want.

## Scope

In scope: this repository's code and the GitHub Action it publishes, for example a way to make
the scanner leak a secret value into a log, comment, issue or report, to run attacker-controlled
code on the runner, or to bypass the checksum verification of downloaded scanners.

Out of scope: vulnerabilities in the third-party scanners it downloads (report those to their
projects), and findings the scanners report about your own code.
