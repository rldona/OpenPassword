package io.github.rldona.openpassword.images

import android.content.Context
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.net.Uri
import android.os.Build
import io.github.rldona.openpassword.core.attachmentLimits
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.OutputStream
import java.nio.ByteBuffer
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * Turns a picked or captured image into the small, metadata-free JPEG the vault stores.
 *
 * Everything happens in memory: no cache file, no gallery write. The output is always
 * re-encoded, so EXIF, GPS, XMP and HDR gain maps from the source never reach the core.
 */
object ImagePipeline {
    /** Largest side kept. Enough to read a DNI or a card; small enough for a backup. */
    const val MAX_SIDE = 2048
    /** Refuse absurd sources before allocating their pixels (decompression bombs). */
    private const val MAX_PIXELS = 50_000_000L
    private val QUALITIES = intArrayOf(80, 70, 60)
    private val STEPS = intArrayOf(MAX_SIDE, 1600, 1280)

    suspend fun fromUri(context: Context, uri: Uri): ByteArray? = withContext(Dispatchers.Default) {
        runCatching {
            process(ImageDecoder.createSource(context.contentResolver, uri))
        }.getOrNull()
    }

    /** Used for the in-app camera, whose JPEG arrives in memory. */
    suspend fun fromBytes(bytes: ByteArray): ByteArray? = withContext(Dispatchers.Default) {
        runCatching { process(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) }.getOrNull()
    }

    private fun process(source: ImageDecoder.Source): ByteArray? {
        val maxBytes = attachmentLimits().maxImageBytes.toInt()
        var bitmap = ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            if (info.size.width.toLong() * info.size.height.toLong() > MAX_PIXELS) {
                throw IllegalArgumentException("image too large")
            }
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            decoder.isMutableRequired = true
            val longest = max(info.size.width, info.size.height)
            if (longest > MAX_SIDE) {
                decoder.setTargetSampleSize((longest + MAX_SIDE - 1) / MAX_SIDE)
            }
        }
        // An Ultra HDR gain map survives Bitmap.compress and would add metadata to the JPEG.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            bitmap.gainmap = null
        }
        try {
            for (side in STEPS) {
                bitmap = downscale(bitmap, side)
                for (quality in QUALITIES) {
                    val jpeg = compress(bitmap, quality)
                    if (jpeg.size <= maxBytes) return jpeg
                    jpeg.fill(0)
                }
            }
            return null
        } finally {
            bitmap.recycle()
        }
    }

    private fun downscale(bitmap: Bitmap, side: Int): Bitmap {
        val longest = max(bitmap.width, bitmap.height)
        if (longest <= side) return bitmap
        val scale = side.toFloat() / longest
        val width = max(1, (bitmap.width * scale).roundToInt())
        val height = max(1, (bitmap.height * scale).roundToInt())
        val scaled = Bitmap.createScaledBitmap(bitmap, width, height, true)
        if (scaled !== bitmap) bitmap.recycle()
        return scaled
    }

    private fun compress(bitmap: Bitmap, quality: Int): ByteArray {
        val out = WipingByteArrayOutputStream()
        try {
            bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
            return out.toByteArray()
        } finally {
            out.wipe()
        }
    }
}

/** A ByteArrayOutputStream whose growing buffer is wiped after use. */
private class WipingByteArrayOutputStream : OutputStream() {
    private var buffer = ByteArray(64 * 1024)
    private var count = 0

    override fun write(b: Int) {
        ensure(1)
        buffer[count++] = b.toByte()
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        ensure(len)
        System.arraycopy(b, off, buffer, count, len)
        count += len
    }

    fun toByteArray(): ByteArray = buffer.copyOf(count)

    fun wipe() {
        buffer.fill(0)
        count = 0
    }

    private fun ensure(extra: Int) {
        if (count + extra <= buffer.size) return
        var size = buffer.size
        while (size < count + extra) size *= 2
        val grown = buffer.copyOf(size)
        buffer.fill(0)
        buffer = grown
    }
}
