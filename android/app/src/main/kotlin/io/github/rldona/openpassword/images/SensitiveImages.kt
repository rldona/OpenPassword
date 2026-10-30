package io.github.rldona.openpassword.images

import android.graphics.Bitmap
import android.graphics.Color
import java.util.Collections
import java.util.WeakHashMap

/**
 * Tracks the bitmaps that may hold a decrypted image, so locking the vault wipes them even if
 * a screen is still composed. Every image bitmap must be registered after decoding and the
 * owner should unregister and recycle it on dispose.
 */
object SensitiveImages {
    private val bitmaps: MutableSet<Bitmap> =
        Collections.synchronizedSet(Collections.newSetFromMap(WeakHashMap<Bitmap, Boolean>()))

    fun register(bitmap: Bitmap) {
        bitmaps.add(bitmap)
    }

    fun unregister(bitmap: Bitmap) {
        bitmaps.remove(bitmap)
    }

    /** Fills every tracked bitmap with transparent pixels and recycles it. */
    fun wipeAll() {
        synchronized(bitmaps) {
            bitmaps.forEach { bitmap ->
                runCatching {
                    bitmap.eraseColor(Color.TRANSPARENT)
                    bitmap.recycle()
                }
            }
            bitmaps.clear()
        }
    }
}
