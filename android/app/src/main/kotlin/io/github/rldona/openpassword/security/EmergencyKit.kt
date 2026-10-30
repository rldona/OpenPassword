package io.github.rldona.openpassword.security

import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import java.io.ByteArrayOutputStream
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * One A4 page to print and keep with important documents: the secret key, room to
 * write the master password by hand, and how to restore a backup.
 * Built with the platform PdfDocument: no dependencies, nothing leaves the device.
 */
object EmergencyKit {
    private const val WIDTH = 595 // A4 in PostScript points
    private const val HEIGHT = 842
    private const val MARGIN = 48f
    private val ACCENT = Color.rgb(0x0E, 0x6B, 0x5C)
    private val INK = Color.rgb(0x15, 0x20, 0x1D)
    private val MUTED = Color.rgb(0x5A, 0x67, 0x63)
    private val LINE = Color.rgb(0xB8, 0xC3, 0xBF)

    fun pdf(secretKey: String, date: LocalDate = LocalDate.now()): ByteArray {
        val doc = PdfDocument()
        val page = doc.startPage(PdfDocument.PageInfo.Builder(WIDTH, HEIGHT, 1).create())
        draw(page.canvas, secretKey, date)
        doc.finishPage(page)
        return ByteArrayOutputStream().use { out ->
            doc.writeTo(out)
            doc.close()
            out.toByteArray()
        }
    }

    private fun draw(c: Canvas, secretKey: String, date: LocalDate) {
        val content = WIDTH - 2 * MARGIN
        var y = MARGIN

        // Header band
        c.drawRect(0f, 0f, WIDTH.toFloat(), 96f, Paint().apply { color = ACCENT })
        c.drawText("OpenPassword", MARGIN, 46f, text(26f, Color.WHITE, bold = true))
        c.drawText("Kit de emergencia", MARGIN, 74f, text(15f, Color.WHITE))
        val dateText = "Creado el " + date.format(DateTimeFormatter.ofPattern("d 'de' MMMM 'de' yyyy", Locale.forLanguageTag("es")))
        val datePaint = text(11f, Color.WHITE)
        c.drawText(dateText, WIDTH - MARGIN - datePaint.measureText(dateText), 74f, datePaint)
        y = 128f

        y = paragraph(
            c, y, content,
            "Con este papel y tu contraseña maestra puedes recuperar tus datos en otro teléfono a partir de una copia " +
                "de seguridad (.opvault). Sin los dos, nadie puede descifrarla: tampoco nosotros.",
            text(11.5f, INK),
        ) + 22f

        // Secret key box
        y = label(c, y, "CLAVE SECRETA")
        val box = RectF(MARGIN, y, WIDTH - MARGIN, y + 70f)
        c.drawRoundRect(box, 8f, 8f, Paint().apply { color = Color.rgb(0xEE, 0xF5, 0xF3) })
        c.drawRoundRect(box, 8f, 8f, Paint().apply { color = ACCENT; style = Paint.Style.STROKE; strokeWidth = 1.5f })
        val keyPaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
            color = INK
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            letterSpacing = 0.04f
        }
        // Shrink until the whole key fits inside the box: a truncated key is useless.
        val maxWidth = box.width() - 32f
        var size = 22f
        do {
            keyPaint.textSize = size
            size -= 0.5f
        } while (keyPaint.measureText(secretKey) > maxWidth && size > 8f)
        val keyX = box.left + (box.width() - keyPaint.measureText(secretKey)) / 2
        c.drawText(secretKey, keyX, box.centerY() + keyPaint.textSize / 3, keyPaint)
        y = box.bottom + 8f
        y = paragraph(c, y, content, "Las letras O, I y L no se usan: si dudas, es un cero o un uno.", text(10f, MUTED)) + 24f

        // Master password, by hand
        y = label(c, y, "CONTRASEÑA MAESTRA (OPCIONAL, A MANO)")
        val linePaint = Paint().apply { color = LINE; strokeWidth = 1f }
        repeat(2) {
            y += 30f
            c.drawLine(MARGIN, y, WIDTH - MARGIN, y, linePaint)
        }
        y += 8f
        y = paragraph(
            c, y, content,
            "Escríbela solo si vas a guardar este papel en un lugar realmente seguro. Quien tenga el papel con la " +
                "contraseña y una copia de tu caja fuerte podrá abrirla.",
            text(10f, MUTED),
        ) + 26f

        // How to restore
        y = label(c, y, "CÓMO RECUPERAR TUS DATOS")
        val steps = listOf(
            "Instala OpenPassword en el teléfono nuevo y elige «Restaurar una copia de seguridad».",
            "Elige tu fichero .opvault (de tu ordenador, una tarjeta SD o tu nube).",
            "Escribe la clave secreta de este papel y tu contraseña maestra.",
        )
        steps.forEachIndexed { i, step ->
            c.drawText("${i + 1}.", MARGIN, y + 13f, text(11.5f, ACCENT, bold = true))
            y = paragraph(c, y, content - 20f, step, text(11.5f, INK), x = MARGIN + 20f) + 6f
        }
        y += 4f
        y = paragraph(
            c, y, content,
            "Sin la app también puedes descifrar la copia con la herramienta de código abierto «opvault decrypt» " +
                "(github.com/rldona/OpenPassword).",
            text(10.5f, MUTED),
        ) + 26f

        // Keep it safe
        y = label(c, y, "GUÁRDALO BIEN")
        listOf(
            "Imprímelo y guárdalo con tus documentos importantes, o dáselo a alguien de confianza.",
            "Borra el PDF del teléfono después de imprimirlo. No lo subas a la nube ni le hagas fotos.",
            "Si pierdes este papel y tu contraseña maestra, tus copias no se podrán abrir.",
        ).forEach { line ->
            c.drawText("•", MARGIN, y + 13f, text(11.5f, ACCENT, bold = true))
            y = paragraph(c, y, content - 20f, line, text(11.5f, INK), x = MARGIN + 20f) + 6f
        }

        val footer = "OpenPassword es software libre (GPL-3.0-or-later)."
        c.drawText(footer, MARGIN, HEIGHT - 32f, text(9f, MUTED))
    }

    private fun text(size: Float, color: Int, bold: Boolean = false) = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = size
        this.color = color
        typeface = Typeface.create(Typeface.SANS_SERIF, if (bold) Typeface.BOLD else Typeface.NORMAL)
    }

    private fun label(c: Canvas, y: Float, text: String): Float {
        val p = text(9.5f, MUTED, bold = true).apply { letterSpacing = 0.12f }
        c.drawText(text, MARGIN, y + 10f, p)
        return y + 20f
    }

    /** Draws wrapped text at [y] and returns the y just below it. */
    private fun paragraph(c: Canvas, y: Float, width: Float, text: String, paint: TextPaint, x: Float = MARGIN): Float {
        val layout = StaticLayout.Builder.obtain(text, 0, text.length, paint, width.toInt())
            .setAlignment(Layout.Alignment.ALIGN_NORMAL)
            .setLineSpacing(2f, 1f)
            .build()
        c.save()
        c.translate(x, y)
        layout.draw(c)
        c.restore()
        return y + layout.height
    }
}
