package ragewarden.ragedroid.identities

import android.app.Application
import androidx.fragment.app.FragmentActivity
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.core.util.Callback
import com.yubico.yubikit.core.util.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

object YubiKitTransport {
    @Volatile private var manager: YubiKitManager? = null
    @Volatile private var usbStarted: Boolean = false

    /**
     * The USB key plugged in right now, kept from its attach until it closes:
     * a key that was already in the port when a prompt opened is used at once
     * instead of being missed because no new attach event arrives.
     */
    internal val presentUsbKey = PresentKey()

    fun startUsbDiscovery(application: Application) {
        ensureManager(application)
        if (usbStarted) return
        synchronized(this) {
            if (usbStarted) return
            val mgr = manager ?: return
            mgr.startUsbDiscovery(UsbConfiguration().handlePermissions(true)) { device ->
                presentUsbKey.attached(device)
                device.setOnClosed { presentUsbKey.detached(device) }
            }
            usbStarted = true
        }
    }

    fun stopUsbDiscovery() {
        synchronized(this) {
            if (!usbStarted) return
            manager?.stopUsbDiscovery()
            usbStarted = false
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun awaitYubiKey(
        activity: FragmentActivity,
        timeoutMs: Long = 30_000,
    ): YubiKeyDevice {
        val app = activity.applicationContext as Application
        ensureManager(app)
        startUsbDiscovery(app)
        val mgr = manager ?: error("YubiKitManager not initialized")
        val nfcStarted = AtomicBoolean(false)
        try {
            return withTimeout(timeoutMs) {
                coroutineScope {
                    val nfcDeferred = async(Dispatchers.Main) {
                        suspendCancellableCoroutine<YubiKeyDevice?> { cont ->
                            try {
                                mgr.startNfcDiscovery(NfcConfiguration(), activity) { device ->
                                    if (cont.isActive) cont.resume(device)
                                }
                                nfcStarted.set(true)
                            } catch (_: NfcNotAvailable) {
                                if (cont.isActive) cont.resume(null)
                            }
                        }
                    }
                    val usbDeferred = async { presentUsbKey.next() }
                    val device = select<YubiKeyDevice?> {
                        nfcDeferred.onAwait { it }
                        usbDeferred.onAwait { it }
                    }
                    nfcDeferred.cancel()
                    usbDeferred.cancel()
                    device ?: presentUsbKey.next()
                }
            }
        } finally {
            if (nfcStarted.get()) {
                runCatching { mgr.stopNfcDiscovery(activity) }
            }
        }
    }

    suspend fun <T> withSmartCard(
        device: YubiKeyDevice,
        block: suspend (SmartCardConnection) -> T,
    ): T = withContext(Dispatchers.IO) {
        val connection = openConnection(device, SmartCardConnection::class.java)
        try {
            block(connection)
        } finally {
            runCatching { connection.close() }
        }
    }

    private suspend fun <T : YubiKeyConnection> openConnection(
        device: YubiKeyDevice,
        cls: Class<T>,
    ): T = suspendCancellableCoroutine { cont ->
        val cb = Callback<Result<T, IOException>> { result ->
            try {
                cont.resume(result.value)
            } catch (e: IOException) {
                cont.resumeWithException(e)
            } catch (t: Throwable) {
                cont.resumeWithException(t)
            }
        }
        device.requestConnection(cls, cb)
    }

    private fun ensureManager(application: Application) {
        if (manager == null) {
            synchronized(this) {
                if (manager == null) {
                    manager = YubiKitManager(application.applicationContext)
                }
            }
        }
    }
}

/** The one USB YubiKey currently attached, if any. */
internal class PresentKey {
    private val current = kotlinx.coroutines.flow.MutableStateFlow<YubiKeyDevice?>(null)

    fun attached(device: YubiKeyDevice) {
        current.value = device
    }

    fun detached(device: YubiKeyDevice) {
        current.compareAndSet(device, null)
    }

    /** The attached key now, or the next one plugged in. */
    suspend fun next(): YubiKeyDevice = current.filterNotNull().first()
}
