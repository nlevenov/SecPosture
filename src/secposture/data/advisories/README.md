# Advisory data

Each `*.json` file here is an advisory in [OSV format](https://ossf.github.io/osv-schema/).
They are loaded at audit time and matched against installed packages using the
target's native (dpkg / rpm) version comparison.

`sample-CVE-2021-3156.json` is a single real example (the "Baron Samedit" sudo
vulnerability) so the feature works out of the box and the tests have known
data. **Replace this directory with a real feed** for production use, for
example an export of the OSV database for your distribution
(`https://osv-vulnerabilities.storage.googleapis.com/`), or enable the live
OSV API with `advisories.use_osv_api: true`.
