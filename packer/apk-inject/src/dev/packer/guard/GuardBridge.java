package dev.packer.guard;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java port of packer/android/GuardBridge.kt, for use in
 * packer/apk-inject -- the no-Flutter-source-available path (see
 * docs/GUIDE.md "Path A: no source, APK only"). Compiled standalone with
 * javac + d8 against android.jar and injected into the target APK as a
 * separate classesN.dex; this is NOT part of the target app's own build.
 *
 * Written in plain Java (not Kotlin) specifically so this module can be
 * built with only a JDK + android.jar -- no Kotlin compiler required --
 * since the whole point of this path is to work with nothing but an
 * already-built APK and standard Android SDK tooling.
 *
 * Logic, algorithm, and every byte-level detail are identical to
 * GuardBridge.kt -- keep the two in sync. See that file's header comment
 * for the full rationale (why key derivation happens here and not in C,
 * the HKDF parameter spec that must match tools/encrypt_snapshot.py, and
 * the verified cross-language HKDF agreement).
 */
public final class GuardBridge {
    private static final String KDF_CONSTANT = "flutter-guard-v1";
    private static final String KDF_INFO = "flutter-guard-v1-libapp-aes256";
    private static final int AES_KEY_LEN = 32;
    private static final int HASH_LEN = 32; // SHA-256

    private GuardBridge() {}

    /**
     * Call once, from GuardApplication.onCreate(), AFTER
     * FlutterLoader().startInitialization(context) has returned. See
     * GuardApplication's class doc for the full required ordering.
     *
     * Deliberately does NOT catch exceptions here (matches GuardBridge.kt):
     * a failure here (e.g. cert reading) left uncaught crashes the app
     * immediately in Application.onCreate() with a clear Java stack trace
     * pointing at the actual cause. Swallowing it would only delay the
     * same crash to engine-init time, where it surfaces as an opaque
     * native "wrong snapshot version" failure deep in the Dart VM instead
     * -- strictly worse for debugging, not actually safer.
     */
    public static void install(Context context) throws Exception {
        System.loadLibrary("guard");

        byte[] certDer = readCurrentSigningCertDer(context);
        byte[] ikm = concat(sha256(certDer), KDF_CONSTANT.getBytes(StandardCharsets.UTF_8));
        byte[] key = hkdfSha256(ikm, new byte[0], KDF_INFO.getBytes(StandardCharsets.UTF_8), AES_KEY_LEN);
        nativeSetKey(key);
    }

    /**
     * Returns the DER bytes of the certificate the CURRENTLY installed APK
     * is actually signed with -- i.e. whatever you re-signed the packed
     * APK with (see tools/build_and_pack.sh / pack_existing_apk.sh), NOT
     * the original app's certificate (which is unknown/unavailable in the
     * no-source path). Uses `apkContentsSigners` (API 28+) rather than
     * `signingCertificateHistory` -- see GuardBridge.kt's comment on why.
     */
    private static byte[] readCurrentSigningCertDer(Context context) throws Exception {
        PackageManager pm = context.getPackageManager();
        String pkg = context.getPackageName();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo signingInfo = info.signingInfo;
            if (signingInfo == null) throw new IllegalStateException("GuardBridge: signingInfo is null");
            Signature[] signers = signingInfo.getApkContentsSigners();
            if (signers == null || signers.length == 0) {
                throw new IllegalStateException("GuardBridge: no apkContentsSigners found");
            }
            return signers[0].toByteArray();
        } else {
            @SuppressWarnings("deprecation")
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            @SuppressWarnings("deprecation")
            Signature[] signatures = info.signatures;
            if (signatures == null || signatures.length == 0) {
                throw new IllegalStateException("GuardBridge: no signatures found");
            }
            return signatures[0].toByteArray();
        }
    }

    private static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        // See GuardBridge.kt's comment: empty key and a 64-byte all-zero
        // key are byte-identical HMAC inputs after HMAC's own zero-padding
        // (RFC 5869 HKDF-Extract uses `salt` as the HMAC key, including
        // when salt is empty; javax.crypto just rejects a zero-length key
        // object directly, so substitute the equivalent padded form).
        byte[] effectiveKey = key.length == 0 ? new byte[64] : key;
        mac.init(new SecretKeySpec(effectiveKey, "HmacSHA256"));
        return mac.doFinal(data);
    }

    /** RFC 5869 HKDF-Extract-then-Expand. */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        byte[] prk = hmacSha256(salt, ikm); // Extract: HMAC(key=salt, msg=ikm)
        int n = (length + HASH_LEN - 1) / HASH_LEN;
        if (n > 255) throw new IllegalArgumentException("GuardBridge: HKDF output too long");
        byte[] previousBlock = new byte[0];
        byte[] okm = new byte[n * HASH_LEN];
        for (int i = 1; i <= n; i++) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(previousBlock);
            mac.update(info);
            mac.update((byte) i);
            previousBlock = mac.doFinal();
            System.arraycopy(previousBlock, 0, okm, (i - 1) * HASH_LEN, HASH_LEN);
        }
        byte[] result = new byte[length];
        System.arraycopy(okm, 0, result, 0, length);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Implemented in native/libguard/src/guard.c. `key` must be exactly
     * AES_KEY_LEN (32) bytes. */
    private static native void nativeSetKey(byte[] key);
}
