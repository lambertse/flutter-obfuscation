package dev.packer.guard

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Kotlin half of key derivation (Handover.md §8). Reads the release signing
 * cert via PackageManager, then HKDF-SHA256 derives the AES-256 key that
 * native/libguard/src/trampoline.c uses to decrypt the AOT snapshot.
 *
 * Why here and not in C: this needs a live Context/PackageManager, which is
 * only reachable from Java/Kotlin (or via hidden-API reflection tricks from
 * native code -- deliberately avoided, see README "why key derivation is in
 * Kotlin"). Doing the SHA-256/HMAC hashing here too means libguard.so only
 * vendors ONE crypto primitive (AES, for the actual snapshot decrypt), not
 * a second one bolted on purely for key derivation.
 *
 * MUST match tools/encrypt_snapshot.py's derive_key_from_cert() byte-for-
 * byte -- see that file's header comment for the shared parameter spec
 * (KDF_CONSTANT, KDF_INFO, salt, output length). This repo has no
 * JVM/emulator available to verify that cross-language agreement directly
 * -- see README "Known limitations (v1)" -- add a unit test asserting both
 * sides produce the same key for a fixed test certificate before shipping.
 *
 * ORDERING, and why loadLibrary is NOT in an `init` block here: guard.c's
 * constructor patches the dlopen GOT slot *inside libflutter.so*, which
 * means libflutter.so must already be mapped into the process before
 * `System.loadLibrary("guard")` runs -- otherwise `dl_iterate_phdr` finds
 * no such module, the hook install fails, and guard_ctor() aborts the
 * process (fail-closed, by design). A plain Application with no explicit
 * step loads libflutter.so lazily, later, during FlutterActivity's own
 * engine init -- well after class-load time. So this is NOT triggered
 * automatically by referencing GuardBridge early; call install() from
 * App.kt only AFTER System.loadLibrary("flutter") has run there. See
 * App.kt for the full required sequence and why that's a direct
 * System.loadLibrary call rather than going through Flutter's own
 * FlutterLoader Java class.
 */
object GuardBridge {
    private const val KDF_CONSTANT = "flutter-guard-v1"
    private const val KDF_INFO = "flutter-guard-v1-libapp-aes256"
    private const val AES_KEY_LEN = 32
    private const val HASH_LEN = 32 // SHA-256

    /**
     * Call once, from Application.onCreate(), AFTER
     * System.loadLibrary("flutter") has run there (that loads libflutter.so;
     * see class doc above for why the order matters, and why it's a direct
     * System.loadLibrary call rather than Flutter's own FlutterLoader).
     * Loads libguard.so (runs its GOT-hook constructor), then derives and
     * installs the AES key. Both must complete before any FlutterEngine is
     * created / any FlutterActivity starts -- App.kt's onCreate() ordering
     * guarantees that on the standard Android app-startup sequence.
     */
    fun install(context: Context) {
        System.loadLibrary("guard")

        val certDer = readCurrentSigningCertDer(context)
        val ikm = sha256(certDer) + KDF_CONSTANT.toByteArray(Charsets.UTF_8)
        val key = hkdfSha256(
            ikm = ikm,
            salt = ByteArray(0),
            info = KDF_INFO.toByteArray(Charsets.UTF_8),
            length = AES_KEY_LEN,
        )
        // Non-secret fingerprints to diagnose a build-vs-runtime key
        // mismatch: encrypt_snapshot.py prints the SAME two fingerprints at
        // pack time. cert-fp differs => APK signed with a different cert than
        // the packer derived the key from; cert-fp matches but key-fp differs
        // => Java/Python HKDF disagree. Only 4 bytes of each SHA-256 logged.
        Log.i("libguard", "GuardBridge: cert-fp=${fp(certDer)} key-fp=${fp(key)}")
        nativeSetKey(key)
    }

    private fun fp(data: ByteArray): String =
        sha256(data).take(4).joinToString("") { "%02x".format(it) }

    /**
     * Returns the DER bytes of the certificate the CURRENTLY installed APK
     * is actually signed with. Deliberately uses `apkContentsSigners`
     * (API 28+) rather than `signingCertificateHistory`: history returns a
     * key-rotation *lineage*, which for a rotated app would give a
     * different (older) certificate than the one the release build was
     * just signed with -- and a mismatch here means a DIFFERENT key than
     * tools/encrypt_snapshot.py derived, which bricks the app. If your app
     * uses multiple APK signers this takes the first one; make sure that
     * matches what --keystore/--key-alias export in build_and_pack.sh.
     */
    private fun readCurrentSigningCertDer(context: Context): ByteArray {
        val pm = context.packageManager
        val pkg = context.packageName
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            val signers = info.signingInfo?.apkContentsSigners
            require(!signers.isNullOrEmpty()) { "GuardBridge: no apkContentsSigners found" }
            signers[0].toByteArray()
        } else {
            @Suppress("DEPRECATION")
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            val signatures = info.signatures
            require(!signatures.isNullOrEmpty()) { "GuardBridge: no signatures found" }
            signatures[0].toByteArray()
        }
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // RFC 5869 HKDF-Extract uses `salt` as the HMAC key, including when
        // salt is empty -- but javax.crypto rejects a zero-length
        // SecretKeySpec. HMAC pads any key shorter than the hash's block
        // size (64 bytes for SHA-256) with zeros before use, so an empty
        // key and a 64-byte all-zero key are byte-identical after that
        // padding step: substituting one for the other is not a shortcut,
        // it is the same HMAC input.
        val effectiveKey = if (key.isEmpty()) ByteArray(64) else key
        mac.init(SecretKeySpec(effectiveKey, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 HKDF-Extract-then-Expand. */
    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(salt, ikm) // Extract: HMAC(key=salt, msg=ikm)
        val n = (length + HASH_LEN - 1) / HASH_LEN
        require(n <= 255) { "GuardBridge: HKDF output too long" }
        var previousBlock = ByteArray(0)
        val okm = ByteArray(n * HASH_LEN)
        for (i in 1..n) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previousBlock)
            mac.update(info)
            mac.update(i.toByte())
            previousBlock = mac.doFinal()
            previousBlock.copyInto(okm, (i - 1) * HASH_LEN)
        }
        return okm.copyOf(length)
    }

    /** Implemented in native/libguard/src/guard.c. `key` must be exactly
     * AES_KEY_LEN (32) bytes. */
    private external fun nativeSetKey(key: ByteArray)
}
