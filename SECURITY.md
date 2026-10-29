# Security Policy

cleave parses hostile input by design. A crash, hang, unbounded allocation,
sandbox escape, path traversal, or detection bypass triggered by a crafted file
is a security bug.

## Supported versions

Security fixes land on the latest release. Pre-release builds (`-beta`, `-rc`)
are supported until the next release ships.

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/atomdrift-project/cleave/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include the cleave version (`cleave version`), the command line, and a minimal
reproducing input. If the input is live malware, attach it as a zip encrypted
with the password `infected`.

We aim to acknowledge reports within three working days and to ship a fix or
mitigation within 90 days. We will credit you in the advisory unless you ask
us not to.

Detection gaps in the rule set (a sample that should be flagged but is not)
are not vulnerabilities; report those in the
[traits repository](https://github.com/atomdrift-project/traits/issues).
