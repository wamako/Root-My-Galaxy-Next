# SM-S928U / S928USQS6DZH3 diagnostic changes

These changes improve failure reporting. **They do not add validated rooting support for DZH3.**
The corrected fingerprint below is research data, separate from the payload the app downloads.

## Device and observed failure

- Model: `SM-S928U` (`e3q`), product `SM-S928UZTEATT`, locked bootloader.
- Firmware: `S928USQS6DZH3`; build `BP4A.251205.006.S928USQS6DZH3`.
- Kernel: `6.1.145-android14-11-33419968-abS928USQS6DZH3`.
- Android 16 / SDK 36, ARM64, 4096-byte pages.

The supplied DirtyFrag log reports a zero-byte vendor read, failure of the second file patch,
and no observable root. A successful APK build cannot resolve that native failure.

## Changes in the APK

An explicit failed or unknown native result now takes one root-state reading and finishes
without polling or announcing the KernelSU loading phase. A positive root reading still
counts even when the chain reports failure. Results that reached the daemon retain the
existing bounded wait. The native result is logged before verification.

The regression tests cover failures, unexpected results, existing root after a failure,
and late root after a successful chain.

## Fingerprint research

[`p0_fingerprint.h`](p0_fingerprint.h) was regenerated from the uploaded stock kernel.
All 256 sampled 64-bit words were checked against that image. Compared with the DZF2
reference, the word at raw Image offset `0x150200` changes from
`0x9106d0219000b001` to `0x9105c0219000b001`.
[`fingerprint-verification.json`](fingerprint-verification.json) records the hashes and result.

This header is not included by the app or wired into a deployed native payload. It does
not establish exploit compatibility or working root. No new DZH3 payload or support-feed
entry is supplied by this diagnostic build.

The reference layout comes from
[Root-My-Galaxy-Payloads](https://github.com/rushiranpise/Root-My-Galaxy-Payloads/blob/b9a4479a6ebac5d46cf60959697d4bcd851aa727/src/targets/e3q-S928USQS6DZF2/p0_fingerprint.h),
under Apache-2.0, matching this repository's license.

The supplied boot, ABL and vendor-boot images were reassembled and inspected locally.
Their decompressed SHA-256 hashes are:

| Image | SHA-256 |
| --- | --- |
| `boot.img` | `23fa31ab71d366be216c14bdc997cb38a29d16261b34f54fcb63a9b93945f6d2` |
| Raw kernel | `8c9b2084f6e451e81a7816b9c742dd89776b670d82f7c2ed84cd1f2f2a1ae577` |
| `abl.elf` | `45c6846c64262027b316c181bbc99de9ec7d2dd97bffb665da1a051517cc804b` |
| `vendor_boot.img` | `21c8d44a9eab7875ec42e347f015a699a0a849aef3288be050b805ce495c4a86` |

Static image analysis does not establish the live physical placement of the kernel.
The raw firmware and recovered binaries are not committed here.

## Download a diagnostic APK

The **DZH3 diagnostic APK** GitHub Actions workflow runs on `main` pushes and can also
be started manually on `main`. It requires the repository's four signing secrets:
`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, and `KEY_PASSWORD`.

It runs the full JVM suite, builds debug and release APKs, checks both signing certificates,
and publishes a diagnostic prerelease under
[Releases](https://github.com/wamako/Root-My-Galaxy-Next/releases).
Expand **Assets** and download the APK ending in `-debug.apk` for diagnosis. The other APK
is the release build of the same diagnostic changes. `SHA256SUMS` contains their hashes.
Publication occurs only after those checks pass. Export the app's log after testing.

## Build on Linux

Install Git, JDK 21, and the Android SDK command-line tools or Android Studio first.
Set `JAVA_HOME` to your JDK 21 directory and adjust the SDK path below if needed:

```bash
git clone https://github.com/wamako/Root-My-Galaxy-Next.git
cd Root-My-Galaxy-Next
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
sdkmanager --licenses
sdkmanager --install "platform-tools" "platforms;android-37.0" "build-tools;36.0.0" "cmake;3.22.1" "ndk;28.0.13004108"
./gradlew testDebugUnitTest :app:assembleDebug --no-daemon
```

The output is `app/build/outputs/apk/debug/app-debug.apk`. With USB debugging enabled
and the computer authorized on the phone, install it using:

```bash
adb devices
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

A local debug build normally uses Android's debug key. Android will reject an update over
an APK signed with a different key; use the matching signing configuration described in
the repository README when retaining the installed app's data matters. Release builds
require that signing configuration.
