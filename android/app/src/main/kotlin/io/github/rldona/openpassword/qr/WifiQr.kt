package io.github.rldona.openpassword.qr

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** The "WIFI:" text that Android and iOS cameras read to join a network. */
object WifiQr {
    /** No password means an open network; anything else is offered as WPA/WPA2/WPA3. */
    fun payload(ssid: String, password: String): String {
        val security = if (password.isEmpty()) "nopass" else "WPA"
        val pass = if (password.isEmpty()) "" else "P:${escape(password)};"
        return "WIFI:T:$security;S:${escape(ssid)};$pass;"
    }

    private fun escape(s: String) = s.replace(Regex("""([\\;,:"])"""), """\\$1""")

    /** Black on white with a quiet zone, so it scans from a dark-mode screen too. */
    fun bitmap(text: String, size: Int): Bitmap {
        val hints = mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2)
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val pixels = IntArray(size * size) { if (matrix.get(it % size, it / size)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
    }
}
