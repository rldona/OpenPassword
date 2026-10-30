package io.github.rldona.openpassword.session

/**
 * True if an Argon2id run asking for [mKib] KiB fits in the device: it must not exceed half
 * of [totalMemBytes] (the device's RAM). Pure so the edges are testable.
 *
 * This is a loose complement to the native ceiling (`MOBILE_MAXIMUM`, 512 MiB), which is the
 * real barrier; it only matters on devices with little RAM.
 */
fun kdfMemoryFits(mKib: UInt, totalMemBytes: Long): Boolean =
    mKib.toLong() * 1024 <= totalMemBytes / 2
