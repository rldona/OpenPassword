package io.github.rldona.openpassword

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import io.github.rldona.openpassword.qr.QrDecoder
import io.github.rldona.openpassword.qr.TotpScan
import io.github.rldona.openpassword.qr.classifyTotpQr
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class QrDecoderTest {
    private val uri = "otpauth://totp/GitHub:raul@ejemplo.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

    /** QR encoded with ZXing's own writer, with a margin, as an ARGB image. */
    private fun qrPixels(text: String, size: Int = 300, invert: Boolean = false): IntArray {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.MARGIN to 4))
        return IntArray(size * size) { i ->
            val dark = m.get(i % size, i / size) != invert
            if (dark) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
    }

    @Test
    fun decodesAnImage() {
        assertEquals(uri, QrDecoder.fromArgb(qrPixels(uri), 300, 300))
    }

    @Test
    fun decodesADarkModeScreenshot() {
        assertEquals(uri, QrDecoder.fromArgb(qrPixels(uri, invert = true), 300, 300))
    }

    @Test
    fun decodesACameraFrameWithRowPadding() {
        val size = 300
        val stride = 320 // camera buffers often pad rows
        val argb = qrPixels(uri, size)
        val y = ByteArray(stride * size) { 0xFF.toByte() }
        for (row in 0 until size) for (col in 0 until size) {
            y[row * stride + col] = if (argb[row * size + col] == 0xFF000000.toInt()) 0 else 0xFF.toByte()
        }
        assertEquals(uri, QrDecoder.fromLuminance(y, size, size, stride))
    }

    @Test
    fun noQrMeansNull() {
        assertNull(QrDecoder.fromArgb(IntArray(200 * 200) { 0xFFFFFFFF.toInt() }, 200, 200))
    }

    @Test
    fun onlyTotpLinksAreAccepted() {
        assertEquals(TotpScan.Valid(uri), classifyTotpQr("  $uri\n"))
        assertEquals(TotpScan.NotTotp, classifyTotpQr("https://github.com/login"))
        assertEquals(TotpScan.NotTotp, classifyTotpQr("WIFI:S:casa;T:WPA;P:clave;;"))
        assertEquals(TotpScan.NotTotp, classifyTotpQr("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1"))
    }
}
