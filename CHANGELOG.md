# Changelog

## TrueAegis v1.2.0-dev

TrueAegis v1.2 adds compatibility with NetSniper v2 telemetry bundles while preserving legacy `analysis_*.json` workflows.

### Added

- NetSniper run-bundle loading for `manifest.json` and bundle directories.
- Compatibility with `netsniper-run-v2` and `netsniper-run-v3` manifests.
- `bundle_quality.json` awareness for `netsniper-bundle-quality-v1`.
- Default rejection of bundles where `deltaaegis_ready` is false.
- `TRUEAEGIS_ALLOW_UNREADY_BUNDLE=1` / `--allow-unready-bundle` override for fixture and debug review.
- NetSniper source metadata display in terminal output.
- `tools/validate_v1_2_netsniper_v2_compat.sh` fixture-based compatibility validator.

### Compatibility

- Legacy `~/NetSniper/targets/analysis_*.json` workflows remain supported.
- NetSniper v2 bundle fixtures can be validated from `~/NetSniper/examples/deltaaegis-fixtures`.


## TrueAegis v1.1-beta

TrueAegis v1.1 is a major validation-accuracy update focused on producing more reliable, explainable, and actionable findings from NetSniper scan data.

### Added

* Structured validation evidence for every analyzed finding
* Dedicated validation fields for:

  * reachability
  * protocol confirmation
  * exposure state
  * authentication posture
  * transport type
  * confidence level
  * supporting evidence
  * service metadata
* Shared TCP, UDP, TLS, HTTP, and banner-probing helpers
* Dedicated plaintext HTTP and HTTPS validation paths
* TLS handshake validation and metadata collection
* Docker Engine API validation using the `/version` JSON endpoint
* Docker API validation over both HTTP and TLS
* MongoDB wire-protocol validation using a safe `hello` request
* Redis validation using a RESP-formatted `PING` request
* SMB validation with anonymous enumeration checks
* SMB dependency detection with a `DEPENDENCY_MISSING` result when `smbclient` is unavailable
* Portainer candidate fingerprinting for services detected on TCP ports `9000` and `9443`
* A Protected metric in the local web dashboard
* Expanded validation-state reporting in Markdown and PDF reports

### New Validation States

TrueAegis can now distinguish between:

* `CONFIRMED`
* `PROTECTED`
* `PARTIALLY_CONFIRMED`
* `REACHABLE`
* `PROTOCOL_MISMATCH`
* `DEPENDENCY_MISSING`
* `TIMEOUT`
* `INCONCLUSIVE`
* `NOT_REACHABLE`
* `NOT_VALIDATED`

### Changed

* Generic TCP reachability no longer counts as confirmed service exposure
* Open ports without protocol-specific validation are reported as `REACHABLE`
* Protocol mismatches are downgraded instead of being treated as validated findings
* Risk scoring now accounts for validation quality
* Correlation confidence now weighs confirmed, protected, reachable, mismatched, and unreachable findings differently
* HTTP product fingerprinting now checks both plaintext and TLS transports when appropriate
* Portainer exposure is no longer assumed from port number alone
* Dashboard summaries now include protected services
* Generated reports now surface mismatches, missing dependencies, timeouts, and inconclusive results

### Improved

* Reduced false positives from reused service ports
* More accurate web-service classification
* Better differentiation between exposed and authentication-protected services
* Improved compatibility with NetSniper v1.3 candidate findings
* More transparent remediation prioritization
* Better debugging through structured evidence and metadata

### Notes

TrueAegis v1.1 remains a beta release while additional protocol validators, environment scoring, and cross-host intelligence features continue to be developed.

TrueAegis is intended for authorized defensive security analysis only.
