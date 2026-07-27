package com.anto502.velovpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import org.torproject.jni.TorService
// gomobile-generated package for the Orbot-IPtProxy AAR (JitPack: master-SNAPSHOT,
// since that fork has no tagged releases). If the CI build reports
// "unresolved reference: IPtProxy" this import path is the first thing to check
// against the actual jar contents (e.g. `IPtProxy.IPtProxy` vs plain `IPtProxy`).
import IPtProxy.IPtProxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Routes ALL device traffic through Tor: brings the local Tor daemon up
 * (org.torproject:tor-android-binary -> org.torproject.jni.TorService),
 * then captures the device's traffic with a standard Android VpnService
 * tun interface and forwards every packet into Tor's local SOCKS port
 * using IPtProxy's bundled tun2socks. This mirrors how Orbot itself routes
 * whole-device traffic through Tor.
 *
 * NOTE: the exact broadcast action / extra names and the tun2socks entry
 * point below are written against the commonly documented tor-android-binary
 * / IPtProxy APIs. Library versions do drift, so if the CI build reports an
 * "unresolved reference" on TorService.* or IPtProxy.* below, that tells us
 * exactly which symbol needs adjusting for the version Gradle actually
 * resolved — paste that error back and it's a quick fix.
 */
class TorVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.anto502.velovpn.torconnect"
        const val ACTION_DISCONNECT = "com.anto502.velovpn.tordisconnect"
        private const val CHANNEL_ID = "velo_vpn_tor"
        private const val NOTIFICATION_ID = 42
        private const val SOCKS_HOST = "127.0.0.1"
        // Fallback only, used if reading TorService's actual bound port fails.
        private const val SOCKS_PORT_FALLBACK = 9050
        private const val VPN_MTU = 1500
    }

    private var tunFd: ParcelFileDescriptor? = null
    private val tun2socksRunning = AtomicBoolean(false)
    private var torStatusReceiver: BroadcastReceiver? = null
    private var torServiceBinder: TorService? = null
    private var torServiceConnection: ServiceConnection? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                stopSelf()
            }
            else -> startForegroundNotification().also { startTorThenTunnel() }
        }
        return START_STICKY
    }

    private fun startTorThenTunnel() {
        Thread {
            try {
                val bootstrapped = bootstrapTor(timeoutSeconds = 90)
                if (!bootstrapped) {
                    stopSelf()
                    return@Thread
                }
                establishTunAndStartTun2Socks()
            } catch (e: Exception) {
                stopSelf()
            }
        }.start()
    }

    /**
     * Starts and binds to org.torproject.jni.TorService, waiting for it to
     * report status ON. Binding (rather than just startService) lets us read
     * back the actual SOCKS port TorService picked, via getSocksPort() —
     * see guardianproject/tor-android's androidTest suite, which does the
     * same thing.
     */
    private fun bootstrapTor(timeoutSeconds: Long): Boolean {
        val latch = CountDownLatch(1)
        val gotOn = AtomicBoolean(false)

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                val status = intent?.getStringExtra(TorService.EXTRA_STATUS)
                if (status == TorService.STATUS_ON) {
                    gotOn.set(true)
                    latch.countDown()
                } else if (status == TorService.STATUS_OFF) {
                    latch.countDown()
                }
            }
        }
        torStatusReceiver = receiver
        registerReceiver(receiver, IntentFilter(TorService.ACTION_STATUS))

        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                // TorService's binder IS the TorService instance itself
                // (see guardianproject/tor-android sample app).
                torServiceBinder = binder as? TorService
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                torServiceBinder = null
            }
        }
        torServiceConnection = connection
        val svcIntent = Intent(this, TorService::class.java)
        startService(svcIntent)
        bindService(svcIntent, connection, Context.BIND_AUTO_CREATE)

        latch.await(timeoutSeconds, TimeUnit.SECONDS)
        try { unregisterReceiver(receiver) } catch (ignored: Exception) {}
        torStatusReceiver = null
        return gotOn.get()
    }

    private fun establishTunAndStartTun2Socks() {
        val builder = Builder()
            .setSession("Velo VPN (Tor)")
            .setMtu(VPN_MTU)
            .addAddress("10.0.10.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")

        val pfd = builder.establish() ?: return
        tunFd = pfd
        tun2socksRunning.set(true)

        val socksPort = try {
            torServiceBinder?.socksPort ?: SOCKS_PORT_FALLBACK
        } catch (e: Exception) {
            SOCKS_PORT_FALLBACK
        }

        // Hands the tun file descriptor to the Orbot-IPtProxy fork's bundled
        // tun2socks, which reads/writes raw IP packets on the fd and forwards
        // the TCP/UDP streams inside them to Tor's local SOCKS proxy.
        IPtProxy.Tun2socks.start(
            /* fd = */ pfd.fd.toLong(),
            /* mtu = */ VPN_MTU.toLong(),
            /* socksServerAddr = */ "$SOCKS_HOST:$socksPort",
            /* socksUsername = */ "",
            /* socksPassword = */ "",
            /* udpgwServerAddr = */ "",
            /* udpgwTransparentDNS = */ false
        )
    }

    private fun stopTunnel() {
        if (tun2socksRunning.getAndSet(false)) {
            try { IPtProxy.Tun2socks.stop() } catch (ignored: Exception) {}
        }
        try { tunFd?.close() } catch (ignored: Exception) {}
        tunFd = null
        torServiceConnection?.let {
            try { unbindService(it) } catch (ignored: Exception) {}
        }
        torServiceConnection = null
        torServiceBinder = null
        try { stopService(Intent(this, TorService::class.java)) } catch (ignored: Exception) {}
        torStatusReceiver?.let {
            try { unregisterReceiver(it) } catch (ignored: Exception) {}
        }
    }

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr?.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Velo VPN (Tor)", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Velo VPN")
            .setContentText("Routing traffic through Tor")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }
}
