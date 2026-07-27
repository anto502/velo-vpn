package com.anto502.velovpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.BroadcastReceiver
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import org.torproject.jni.TorService
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Bootstraps the real Tor daemon (info.guardianproject:tor-android's
 * org.torproject.jni.TorService) and exposes its local SOCKS proxy.
 *
 * This does NOT capture or route all device traffic (that would need a
 * VpnService + tun2socks, which we deliberately left out — see chat history).
 * Once running, other network calls in the app can be pointed at
 * 127.0.0.1:<getSocksPort()> as a SOCKS5 proxy to go over Tor.
 */
class TorEngineService : Service() {

    companion object {
        const val ACTION_START = "com.anto502.velovpn.tor.start"
        const val ACTION_STOP = "com.anto502.velovpn.tor.stop"
        private const val CHANNEL_ID = "velo_vpn_tor_engine"
        private const val NOTIFICATION_ID = 43

        // Read by VeloVpnPlugin.getTorStatus() — simplest possible way to
        // expose current state without wiring up a full event/broadcast bus.
        @Volatile var isBootstrapped: Boolean = false
            private set
        @Volatile var socksPort: Int = -1
            private set
    }

    private var torServiceBinder: TorService? = null
    private var torServiceConnection: ServiceConnection? = null
    private var torStatusReceiver: BroadcastReceiver? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTor()
                stopSelf()
            }
            else -> {
                startForegroundNotification()
                startTor()
            }
        }
        return START_STICKY
    }

    private fun startTor() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.getStringExtra(TorService.EXTRA_STATUS)) {
                    TorService.STATUS_ON -> {
                        isBootstrapped = true
                        socksPort = try {
                            torServiceBinder?.socksPort ?: -1
                        } catch (e: Exception) {
                            -1
                        }
                        updateNotification("Tor connected (SOCKS $socksPort)")
                    }
                    TorService.STATUS_OFF -> {
                        isBootstrapped = false
                        socksPort = -1
                    }
                }
            }
        }
        torStatusReceiver = receiver
        registerReceiver(receiver, IntentFilter(TorService.ACTION_STATUS))

        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
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
    }

    private fun stopTor() {
        isBootstrapped = false
        socksPort = -1
        torServiceConnection?.let {
            try { unbindService(it) } catch (ignored: Exception) {}
        }
        torServiceConnection = null
        torServiceBinder = null
        torStatusReceiver?.let {
            try { unregisterReceiver(it) } catch (ignored: Exception) {}
        }
        torStatusReceiver = null
        try { stopService(Intent(this, TorService::class.java)) } catch (ignored: Exception) {}
    }

    private fun startForegroundNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr?.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Velo VPN (Tor)", NotificationManager.IMPORTANCE_LOW)
            )
        }
        startForeground(NOTIFICATION_ID, buildNotification("Starting Tor…"))
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr?.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Velo VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()

    override fun onDestroy() {
        stopTor()
        super.onDestroy()
    }
}
