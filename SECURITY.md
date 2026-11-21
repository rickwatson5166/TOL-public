# Security

TOL is made by one person. I will read every report and answer as soon as I can. There is no bounty.

**To report a security problem:** email optioncsolutions@gmail.com with "TOL security" in the subject. Please do not post it as a public issue
until we have talked. Tell me what you did, what you expected, and what happened.

**What is in scope:** the local dashboard server (it listens only on 127.0.0.1 and checks a token, a cookie and the Host header), the evidence-package
checker (`verify.py`), the Firefox add-on's helper, and the way TOL stores files in `~/.tol`.

**What TOL says it does not do:** it does not block anything, read traffic contents or protect you from other software on your computer.
A report that TOL fails at something it never claimed is still welcome, but it is a request, not a vulnerability.

**Supported versions:** the latest release only.
