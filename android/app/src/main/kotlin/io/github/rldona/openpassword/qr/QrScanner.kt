package io.github.rldona.openpassword.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageDecoder
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import io.github.rldona.openpassword.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Scans a TOTP setup QR with the back camera. The camera permission is requested here,
 * when the user asked to scan, never before. Frames are decoded on the device and dropped.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScanScreen(onResult: (String) -> Unit, onCancel: () -> Unit, onPickImage: () -> Unit) {
    val context = LocalContext.current
    var granted by remember { mutableStateOf(hasCameraPermission(context)) }
    var denied by remember { mutableStateOf(false) }
    var notTotp by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        granted = ok
        denied = !ok
    }
    LaunchedEffect(Unit) { if (!granted) permission.launch(Manifest.permission.CAMERA) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.qr_title)) },
                navigationIcon = { IconButton(onClick = onCancel) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_cancel)) } },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (granted) {
                Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CameraPreview(onDecoded = { text ->
                        when (val scan = classifyTotpQr(text)) {
                            is TotpScan.Valid -> onResult(scan.value)
                            TotpScan.NotTotp -> notTotp = true
                        }
                    })
                    Box(Modifier.size(240.dp).border(3.dp, Color.White.copy(alpha = 0.85f), RoundedCornerShape(16.dp)))
                }
                Text(
                    if (notTotp) stringResource(R.string.qr_not_totp)
                    else stringResource(R.string.qr_hint),
                    textAlign = TextAlign.Center,
                    color = if (notTotp) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                Text(
                    if (denied) stringResource(R.string.qr_permission_denied)
                    else stringResource(R.string.qr_permission_rationale),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (denied) {
                    Button(onClick = { permission.launch(Manifest.permission.CAMERA) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.qr_permission_grant)) }
                }
            }
            OutlinedButton(onClick = onPickImage, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.qr_from_image)) }
        }
    }
}

@Composable
private fun CameraPreview(onDecoded: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember { PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER } }
    val executor = remember { Executors.newSingleThreadExecutor() }
    // Report each distinct text once; the camera keeps sending frames.
    val lastText = remember { mutableStateOf<String?>(null) }

    DisposableEffect(lifecycleOwner) {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        val done = AtomicBoolean(false)
        providerFuture.addListener({
            val provider = providerFuture.get()
            val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(executor) { image ->
                image.use {
                    if (done.get()) return@use
                    val plane = it.planes[0]
                    val buffer = plane.buffer
                    val y = ByteArray(buffer.remaining()).also(buffer::get)
                    val text = QrDecoder.fromLuminance(y, it.width, it.height, plane.rowStride)
                    y.fill(0)
                    if (text != null && text != lastText.value) {
                        lastText.value = text
                        if (classifyTotpQr(text) is TotpScan.Valid) done.set(true)
                        ContextCompat.getMainExecutor(context).execute { onDecoded(text) }
                    }
                }
            }
            provider.unbindAll()
            provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            done.set(true)
            runCatching { providerFuture.get().unbindAll() }
            executor.shutdown()
        }
    }
    AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
}

private fun hasCameraPermission(context: Context) =
    ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

/** Decodes a QR from a picked image (screenshot, photo). No permission needed. */
suspend fun decodeQrImage(context: Context, uri: Uri): TotpScan? = withContext(Dispatchers.Default) {
    val bitmap = runCatching {
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(context.contentResolver, uri)) { decoder, info, _ ->
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            // Large photos: a QR needs no more than ~1600 px.
            val longest = maxOf(info.size.width, info.size.height)
            if (longest > MAX_SIDE) decoder.setTargetSampleSize((longest + MAX_SIDE - 1) / MAX_SIDE)
        }
    }.getOrNull() ?: return@withContext null
    val pixels = IntArray(bitmap.width * bitmap.height)
    bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
    val text = QrDecoder.fromArgb(pixels, bitmap.width, bitmap.height)
    bitmap.recycle()
    text?.let(::classifyTotpQr)
}

private const val MAX_SIDE = 1600
