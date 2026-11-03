# Glossary

- **CVE** (Common Vulnerabilities and Exposures): unique ID of a known vulnerability, e.g. `CVE-2021-44228`.
- **CVSS** (Common Vulnerability Scoring System): severity score from 0.0 to 10.0.
- **Severity**: level derived from CVSS - Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0).
- **EPSS** (Exploit Prediction Scoring System): probability, from 0 to 1, that a vulnerability will be exploited in the next 30 days.
- **KEV** (Known Exploited Vulnerabilities): CISA's list of vulnerabilities already exploited in real attacks.
- **Ransomware use**: KEV flag saying the vulnerability is known to be used in ransomware campaigns.
- **NVD**: the US National Vulnerability Database; official details of each CVE.
- **OSV / GitHub Advisories**: databases of vulnerabilities in software packages.
- **Ecosystem**: package world a library belongs to, e.g. Maven (Java) or npm (Node.js).
- **Vendor / product**: who makes the software and its name, e.g. vendor `apache`, product `log4j`.
- **Advisory**: a security notice about a software package, identified by its own id (for example `GHSA-jfh8-c2jp-5v3q`). It may or may not have a CVE.
- **GHSA**: the id format of GitHub's security advisories.
- **Package**: a library published in an ecosystem, such as `org.apache.logging.log4j:log4j-core` in Maven.
- **Fixed version**: a version of a package in which the problem is solved.
- **Withdrawn advisory**: an advisory its authors later retracted. The app does not show them.
- **CPE**: standard text identifying a product and version.
