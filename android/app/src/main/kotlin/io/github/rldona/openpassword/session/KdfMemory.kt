package io.github.rldona.openpassword.session

import android.app.ActivityManager
import android.content.Context
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.importKdf

/**
 * True if an Argon2id run asking for [mKib] KiB fits in the device: it must not exceed half
 * of [totalMemBytes] (the device's RAM). Pure so the edges are testable.
 *
 * This is a loose complement to the native ceiling (`MOBILE_MAXIMUM`, 512 MiB), which is the
 * real barrier; it only matters on devices with little RAM.
 */
fun kdfMemoryFits(mKib: UInt, totalMemBytes: Long): Boolean =
    mKib.toLong() * 1024 <= totalMemBytes / 2

/**
 * Throws [OpException.KdfTooExpensive] if a KeePass database asks for more Argon2 memory than the
 * device has, before any derivation runs. Reads only the plaintext header, so it is cheap.
 *
 * The native ceiling (512 MiB / 3 GiB·pase) is already the hard barrier; this protects devices with
 * little free RAM from an OOM kill. AES-KDF and KDBX 3.1 report no cost and are let through.
 */
fun deviceTotalMemory(context: Context): Long =
    ActivityManager.MemoryInfo().also(context.getSystemService(ActivityManager::class.java)::getMemoryInfo).totalMem

fun checkImportKdfFits(bytes: ByteArray, totalMemBytes: Long) {
    val kdf = importKdf(bytes) ?: return
    if (!kdfMemoryFits(kdf.mKib, totalMemBytes)) throw OpException.KdfTooExpensive(kdf.mKib, kdf.t, kdf.p)
}
