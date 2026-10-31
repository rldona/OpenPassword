package io.github.rldona.openpassword.security

import android.content.res.Resources
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.text.Layout
import android.text.StaticLayout
import android.text.TextPaint
import io.github.rldona.openpassword.R
import java.io.ByteArrayOutputStream
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * One A4 page to print and keep with important documents: the secret key, room to
 * write the master password by hand, and how to restore a backup.
 * Built with the platform PdfDocument: no dependencies, nothing leaves the device.
 *
 * The drawing knows nothing about resources: the caller passes the text already translated
 * ([Text.from]), so the page can be rendered in any language and tested without a Context.
 */
object EmergencyKit {
    private const val WIDTH = 595 // A4 in PostScript points
    private const val HEIGHT = 842
    private const val MARGIN = 48f
    private val ACCENT = Color.rgb(0x0E, 0x6B, 0x5C)
    private val INK = Color.rgb(0x15, 0x20, 0x1D)
    private val MUTED = Color.rgb(0x5A, 0x67, 0x63)
    private val LINE = Color.rgb(0xB8, 0xC3, 0xBF)

    /** Everything the page says, already translated. */
    data class Text(
        val subtitle: String,
        val createdOn: String,
        val intro: String,
        val secretKeyLabel: String,
        val ambiguityNote: String,
        val masterPasswordLabel: String,
        val masterPasswordWarning: String,
        val restoreLabel: String,
        val restoreSteps: List<String>,
        val offlineTool: String,
        val keepSafeLabel: String,
        val keepSafe: List<String>,
        val footer: String,
    ) {
        companion object {
            /** The only place that touches resources. */
            fun from(res: Resources, date: LocalDate = LocalDate.now()): Text {
                val locale = res.configuration.locales[0]
                val formatted = date.format(
                    DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withLocale(locale),
                )
                return Text(
                    subtitle = res.getString(R.string.kit_subtitle),
                    createdOn = res.getString(R.string.kit_created_on, formatted),
                    intro = res.getString(R.string.kit_intro),
                    secretKeyLabel = res.getString(R.string.kit_secret_key_label),
                    ambiguityNote = res.getString(R.string.kit_ambiguity_note),
                    masterPasswordLabel = res.getString(R.string.kit_master_password_label),
                    masterPasswordWarning = res.getString(R.string.kit_master_password_warning),
                    restoreLabel = res.getString(R.string.kit_restore_label),
                    restoreSteps = listOf(
                        res.getString(R.string.kit_restore_step_1, res.getString(R.string.onboarding_restore)),
                        res.getString(R.string.kit_restore_step_2),
                        res.getString(R.string.kit_restore_step_3),
                    ),
                    offlineTool = res.getString(R.string.kit_offline_tool),
                    keepSafeLabel = res.getString(R.string.kit_keep_safe_label),
                    keepSafe = listOf(
                        res.getString(R.string.kit_keep_safe_1),
                        res.getString(R.string.kit_keep_safe_2),
                        res.getString(R.string.kit_keep_safe_3),
                    ),
                    footer = res.getString(R.string.kit_footer),
                )
            }
        }
    }

    fun pdf(text: Text, secretKey: String): ByteArray {
        val doc = PdfDocument()
        val page = doc.startPage(PdfDocument.PageInfo.Builder(WIDTH, HEIGHT, 1).create())
        draw(page.canvas, text, secretKey)
        doc.finishPage(page)
        return ByteArrayOutputStream().use { out ->
            doc.writeTo(out)
            doc.close()
            out.toByteArray()
        }
    }

    private fun draw(c: Canvas, t: Text, secretKey: String) {
        val content = WIDTH - 2 * MARGIN
        var y = MARGIN

        // Header band
        c.drawRect(0f, 0f, WIDTH.toFloat(), 96f, Paint().apply { color = ACCENT })
        c.drawText("OpenPassword", MARGIN, 46f, text(26f, Color.WHITE, bold = true))
        c.drawText(t.subtitle, MARGIN, 74f, text(15f, Color.WHITE))
        val datePaint = text(11f, Color.WHITE)
        c.drawText(t.createdOn, WIDTH - MARGIN - datePaint.measureText(t.createdOn), 74f, datePaint)
        y = 128f

        y = paragraph(c, y, content, t.intro, text(11.5f, INK)) + 22f

        // Secret key box
        y = label(c, y, t.secretKeyLabel)
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
        y = paragraph(c, y, content, t.ambiguityNote, text(10f, MUTED)) + 24f

        // Master password, by hand
        y = label(c, y, t.masterPasswordLabel)
        val linePaint = Paint().apply { color = LINE; strokeWidth = 1f }
        repeat(2) {
            y += 30f
            c.drawLine(MARGIN, y, WIDTH - MARGIN, y, linePaint)
        }
        y += 8f
        y = paragraph(c, y, content, t.masterPasswordWarning, text(10f, MUTED)) + 26f

        // How to restore
        y = label(c, y, t.restoreLabel)
        t.restoreSteps.forEachIndexed { i, step ->
            c.drawText("${i + 1}.", MARGIN, y + 13f, text(11.5f, ACCENT, bold = true))
            y = paragraph(c, y, content - 20f, step, text(11.5f, INK), x = MARGIN + 20f) + 6f
        }
        y += 4f
        y = paragraph(c, y, content, t.offlineTool, text(10.5f, MUTED)) + 26f

        // Keep it safe
        y = label(c, y, t.keepSafeLabel)
        t.keepSafe.forEach { line ->
            c.drawText("•", MARGIN, y + 13f, text(11.5f, ACCENT, bold = true))
            y = paragraph(c, y, content - 20f, line, text(11.5f, INK), x = MARGIN + 20f) + 6f
        }

        c.drawText(t.footer, MARGIN, HEIGHT - 32f, text(9f, MUTED))
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
