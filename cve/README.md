# linux-smart-enumeration CVE checks

LSE can test the host for certain CVEs that might allow privilege escalation.

Each CVE is tested by a specific script, stored in this folder.
To enable CVE checking for LSE, these scripts need to be bundled with `lse.sh`.
This is accomplished by the tool `tools/package_cvs_into_lse.sh`, which creates `lse_cve.sh`.
For LSE on the GitHub Releases page, this has already been done.


## Adding and improving CVE checks

To add a new CVE check, just create a copy of the `skel.sh` script in this folder and fill out the metadata.
Then implement the `lse_cve_test()` function for the specific CVE (get inspiration from existing scripts).
Usually this involves checking and comparing the version of the affected software.
If it looks vulnerable, output something to stdout, otherwise do not.

LSE aims to minimize false positives but for CVE tests, this might require checking backported patches for certain Linux distributions.
This is where improvements are always possible.
If you encounter a false positive, just add the fixed package version for the affected distribution to the script and submit a pull request.

The general workflow for a `lse_cve_test()` function is:
- get the version of the affected software
- if the version is too old or too new to be affected, output nothing and exit
- for some important distributions, list the package version shipping the backported fix
- if installed package version is recent enough, output nothing and exit
- otherwise, it looks vulnerable: output something like "Vulnerable!" and the software version

LSE supports this process with a few helper functions and variables, most notably:
- `lse_is_version_bigger` is true if the first argument is larger than the second according to version sort
- `lse_get_pkg_version` obtains the version of an installed software package
- `$lse_distro_codename` contains the distribution name like `ubuntu`, `debian`, `redhat`, ...


### Sources for researching affected versions

Checking package versions with backported fixes is somewhat optional and nearly impossible to be complete for all existing distributions.
However, it is crucial to eliminate false positives.
The following sources help to determine in which version a distribution patched something.

- Debian: [Security Bug Tracker](https://security-tracker.debian.org/tracker/) allows to search for CVEs and patched versions
- Ubuntu: [Ubuntu Security CVEs](https://ubuntu.com/security/cves) lists CVEs affecting Ubuntu and patched versions
- Fedora: [Koji buildserver](https://koji.fedoraproject.org/koji/) contains a changelog for each package build
- Red Hat Enterprise Linux: [Red Hat CVE Database](https://access.redhat.com/security/security-updates/#/cve) allows to search for CVEs and patched versions
- Amazon Linux: [Amazon Linux Security Center](https://alas.aws.amazon.com/) lists patched versions in their advisories
