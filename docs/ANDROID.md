# Android / hardware-backed keys path

## Goal
Prove the same behavioural vectors on Android and, where the device supports it, bind the agent private key to the Android Keystore (or StrongBox) so the key material never leaves the TEE/SE.

## What is already portable
- Canonical JSON, card signing/verification, request PoP, ReplayGuard, Policy, Gateway decision path, AuditLog, RateLimiter.
- All of the above are pure Kotlin/JVM and compile with the existing `build.gradle.kts` (JDK 17).

## What must be added for Android

### 1. Android library module
```
arachne-guard-kotlin/
  arachne-guard/          # pure JVM (current)
  arachne-guard-android/  # Android library
```

`arachne-guard-android` depends on the JVM module and adds:

- `AndroidKeystoreKeyPair` — generate or load an Ed25519 (or P-256 if Ed25519 is unavailable on older APIs) key inside Android Keystore with `setUserAuthenticationRequired` / StrongBox when present.
- `signCard` / `signRequest` overloads that take a Keystore alias instead of a raw private key.
- A small sample app that pins a card, signs a request, and runs the same SecurityVectorsTest logic on-device.

### 2. Keystore constraints to respect
- Ed25519 support in Android Keystore is API-dependent; fall back to a software key with a clear warning, or use P-256 + a documented algorithm identifier in the card.
- Keys created with `setIsStrongBoxBacked(true)` may fail on devices without StrongBox — handle the exception and degrade.
- Biometric / credential-bound keys require a user presence check before each sign; the agent runtime must be prepared to surface that prompt.

### 3. Proof on CI / device
```bash
# JVM (already possible once wrapper exists)
./gradlew test

# Android instrumentation (on your machine or GitHub Actions with an emulator)
./gradlew :arachne-guard-android:connectedAndroidTest
```

A green `SecurityVectorsTest` on JVM + a green instrumentation run that exercises Keystore-backed signing is the “proved” bar.

### 4. Suggested next implementation order
1. Keep expanding the pure-JVM port until MCP surface + OutputInspector exist and the full Python test matrix has Kotlin counterparts.
2. Add the Android module and Keystore wrapper.
3. Add a minimal sample Activity / WorkManager job that signs one request and verifies the card.
4. Publish an AAR (or Maven coordinate) once the vectors pass on device.

## Non-goals for the first Android cut
- Multi-process shared nonce store
- Full MCP JSON-RPC server on device
- Play Integrity / attestation binding (can be a later hardening layer)
