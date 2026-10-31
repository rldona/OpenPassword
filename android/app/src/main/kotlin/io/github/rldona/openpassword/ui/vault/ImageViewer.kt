package io.github.rldona.openpassword.ui.vault

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.rldona.openpassword.R
import io.github.rldona.openpassword.images.SensitiveImages
import io.github.rldona.openpassword.security.ProtectDialogWindow

/**
 * Decodes a vault image with a pixel ceiling and sampling: a small JPEG can still declare
 * enormous dimensions, and importing a hostile backup must not take the app down.
 */
private fun decodeBounded(bytes: ByteArray): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    if (bounds.outWidth.toLong() * bounds.outHeight.toLong() > 40_000_000L) return null
    var sample = 1
    while (bounds.outWidth / sample > 4096 || bounds.outHeight / sample > 4096) sample *= 2
    val options = BitmapFactory.Options().apply { inSampleSize = sample }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
}

/**
 * Full-screen view of one decrypted image. Only for reading: no share, no save to the gallery,
 * no clipboard. The bitmap is wiped when the dialog closes or the vault locks.
 */
@Composable
fun ImageViewerDialog(bytes: ByteArray, label: String, onClose: () -> Unit) {
    val bitmap = remember(bytes) {
        decodeBounded(bytes)?.also(SensitiveImages::register)
    }
    // The JPEG copy has already been decoded: wipe it now, not when the dialog goes away.
    DisposableEffect(bytes) {
        onDispose { bytes.fill(0) }
    }
    DisposableEffect(bitmap) {
        onDispose {
            bitmap?.let {
                SensitiveImages.unregister(it)
                it.recycle()
            }
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        ProtectDialogWindow()
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            if (bitmap == null) {
                Text(stringResource(R.string.image_viewer_open_failed), modifier = Modifier.align(Alignment.Center), color = Color.White)
            } else {
                var scale by remember { mutableFloatStateOf(1f) }
                var offsetX by remember { mutableFloatStateOf(0f) }
                var offsetY by remember { mutableFloatStateOf(0f) }
                val state = rememberTransformableState { zoomChange, panChange, _ ->
                    scale = (scale * zoomChange).coerceIn(1f, 6f)
                    offsetX += panChange.x
                    offsetY += panChange.y
                }
                Image(
                    bitmap.asImageBitmap(),
                    contentDescription = stringResource(R.string.image_viewer_image_description, label),
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .fillMaxSize()
                        .graphicsLayer(
                            scaleX = scale,
                            scaleY = scale,
                            translationX = offsetX,
                            translationY = offsetY,
                        )
                        .transformable(state),
                )
            }
            IconButton(
                onClick = onClose,
                modifier = Modifier.align(Alignment.TopStart).padding(12.dp),
            ) {
                Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.image_viewer_close), tint = Color.White)
            }
            Text(
                label,
                color = Color.White,
                modifier = Modifier.align(Alignment.BottomCenter).padding(24.dp),
            )
        }
    }
}
