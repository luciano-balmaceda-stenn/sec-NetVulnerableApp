# README

This webapp should raise at minimum 2 of the following 5 vulnerabilities:

## True positive: RestSharp
CVE-2021-27293
https://github.com/advisories/GHSA-9pq7-rcxv-47vq

**Reasoning:** Used in the main method.

## True positive: Newtonsoft.Json
CVE-2024-21907
https://nvd.nist.gov/vuln/detail/CVE-2024-21907

**Reasoning:** Used in a secondary method that is invoked from the main method.

## False positive: AutoMapper
**Reasoning:** It's part of the project dependencies and it's imported, but never used.

## False positive: System.Text.Encodings.Web
CVE-2021-26701
https://nvd.nist.gov/vuln/detail/CVE-2021-26701

**Reasoning:** It's part of the project dependencies but it's not imported nor used.

## False positive: HtmlSanitizer
CVE-2021-26701
https://github.com/advisories/GHSA-43cp-6p3q-2pc4
https://github.com/advisories/GHSA-8j9v-h2vp-2hhv

**Reasoning:** Used in the code, but the method is never invoked.