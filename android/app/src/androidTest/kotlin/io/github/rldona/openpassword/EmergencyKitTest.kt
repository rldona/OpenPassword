package io.github.rldona.openpassword

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rldona.openpassword.security.EmergencyKit
import io.github.rldona.openpassword.security.Wordlist
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class EmergencyKitTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun isOneA4PageWithInk() {
        val pdf = EmergencyKit.pdf("OP1-H7K2Q9-XW4R8T-M3NV6P-2JDL5C-9FBZ7Y")
        assertEquals("%PDF", String(pdf, 0, 4))
        // Sample key only; kept for a visual check with: adb pull <externalFilesDir>/kit-sample.pdf
        context.getExternalFilesDir(null)?.let { File(it, "kit-sample.pdf").writeBytes(pdf) }
        val file = File.createTempFile("kit", ".pdf", context.cacheDir)
        try {
            file.writeBytes(pdf)
            PdfRenderer(ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)).use { renderer ->
                assertEquals(1, renderer.pageCount)
                renderer.openPage(0).use { page ->
                    assertEquals(595, page.width)
                    assertEquals(842, page.height)
                    val bitmap = Bitmap.createBitmap(page.width, page.height, Bitmap.Config.ARGB_8888)
                    bitmap.eraseColor(Color.WHITE)
                    page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_PRINT)
                    // The secret key box sits in the upper third: some row there must be dense with text.
                    val densest = (150 until 330).maxOf { y -> (60 until 535).count { x -> Color.red(bitmap.getPixel(x, y)) < 100 } }
                    assertTrue("fila más densa en la zona de la clave: $densest píxeles oscuros", densest > 40)
                    // Nothing may be drawn past the right margin (48 pt): the key once overflowed the page.
                    val overflow = (150 until 330).sumOf { y -> (548 until 595).count { x -> Color.red(bitmap.getPixel(x, y)) < 200 } }
                    assertEquals("píxeles pintados fuera del margen derecho", 0, overflow)
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun bundledWordlistLoads() {
        val words = Wordlist.eff(context)
        assertEquals(7776, words.size)
        assertTrue(words.contains("abacus"))
    }
}
