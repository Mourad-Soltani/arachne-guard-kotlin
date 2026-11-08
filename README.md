# arachne-guard (Kotlin)

Kotlin/JVM skeleton of [arachne-guard](https://github.com/mouradsoltani/arachne-guard) 0.4.0.

This is a **source-compatible behavioural port** of the verified Python core.
It is intended to be compiled and tested on your machine or in GitHub Actions;
the sandbox environment does not contain a Kotlin toolchain.

## What is implemented

| Component | Status |
|-----------|--------|
| Canonical JSON signing payload | Done |
| Ed25519 agent cards (`signCard` / `verifyCard`) | Done |
| Request proof-of-possession (`signRequest` / `verifyRequest`) | Done |
| ReplayGuard (bounded nonce + clock window) | Done |
| Policy (deny > ask > allow, default deny) | Done |
| TrustStore (pin / revoke) | Done (in-memory) |
| Gateway decision path | Done (audit chain not yet ported) |
| MCP surface / OutputInspector / RateLimiter | Not yet |
| Android Keystore / hardware keys | Not yet |
| Persistent TrustStore + rotation protocol | Not yet |

## Matching test vectors

`src/test/kotlin/com/arachne/guard/SecurityVectorsTest.kt` encodes the same
security properties that the Python suite checks:

- Card signature binds all fields
- Request signature binds agent id + method + params + nonce + ts
- Boolean timestamps are rejected (JSON quirk)
- Replay of a nonce is rejected
- Policy deny overrides allow
- Consent gate fails closed
- Unpinned cards are rejected

A successful port must keep these green.

## Build (on a machine with JDK 17+)

```bash
./gradlew test
./gradlew build
```

If the Gradle wrapper is not present:

```bash
gradle wrapper --gradle-version 8.10
./gradlew test
```

## Relationship to the Python package

The Python package remains the **verified reference**. Any behavioural
divergence is a bug in the Kotlin side until proven otherwise. Once the
remaining modules (MCP, audit chain, output scan) are ported and the full
Python test matrix has Kotlin counterparts, this can become a first-class
artifact for Android / server-side JVM use.

## Licence

MIT — same as the Python package.
