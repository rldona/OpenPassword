package io.github.rldona.openpassword.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/** Reads QR codes from raw pixels. No Android types, so it is unit-testable on the JVM. */
object QrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    /** A camera frame: the Y (luminance) plane, as CameraX delivers it. */
    fun fromLuminance(y: ByteArray, width: Int, height: Int, rowStride: Int = width): String? =
        decode(PlanarYUVLuminanceSource(y, rowStride, height, 0, 0, width, height, false))

    /** An image: ARGB pixels, as Bitmap.getPixels returns them. */
    fun fromArgb(pixels: IntArray, width: Int, height: Int): String? = decode(RGBLuminanceSource(width, height, pixels))

    private fun decode(source: LuminanceSource): String? {
        val reader = QRCodeReader()
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: NotFoundException) {
            // Light text on dark backgrounds (dark-mode screenshots).
            runCatching { reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text }.getOrNull()
        } catch (_: Exception) {
            null
        }
    }
}

/** What a scanned QR means for a TOTP field. */
sealed interface TotpScan {
    data class Valid(val value: String) : TotpScan
    /** A QR, but not a two-factor setup code (a website link, a Wi-Fi code…). */
    data object NotTotp : TotpScan
}

/** Accepts otpauth://totp links only: anything else in a QR is not a 2FA secret. */
fun classifyTotpQr(text: String): TotpScan {
    val t = text.trim()
    return if (t.startsWith("otpauth://totp/", ignoreCase = true)) TotpScan.Valid(t) else TotpScan.NotTotp
}
