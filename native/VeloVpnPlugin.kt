package com.anto502.velovpn

import android.content.Context
import android.content.SharedPreferences
import android.net.VpnService
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

@CapacitorPlugin(name = "VeloVpn")
class VeloVpnPlugin : Plugin() {

    private var backend: GoBackend? = null
    private var tunnel: SimpleTunnel? = null

    private val prefsName = "velo_vpn_wg"
    private val prefsKeyConfig = "wg_config"

    // Retry/backoff tuning for the network calls made during registration and
    // tunnel bring-up. These calls occasionally fail transiently (slow mobile
    // networks, momentary DNS hiccups, carrier-level interference) and a
    // short retry sequence resolves most of those without any user action.
    private val maxNetworkAttempts = 3
    private val baseBackoffMs = 800L

    inner class SimpleTunnel(private val name: String) : Tunnel {
        var state: Tunnel.State = Tunnel.State.DOWN
        override fun getName(): String = name
        override fun onStateChange(newState: Tunnel.State) {
            state = newState
        }
    }

    override fun load() {
        super.load()
        backend = GoBackend(context)
        tunnel = SimpleTunnel("velo")
    }

    @PluginMethod
    fun connect(call: PluginCall) {
        val intent = VpnService.prepare(context)
        if (intent != null) {
            // User has not yet granted VPN permission — launch system consent dialog
            startActivityForResult(call, intent, "vpnPermissionCallback")
            return
        }
        doConnect(call)
    }

    @com.getcapacitor.annotation.ActivityCallback
    private fun vpnPermissionCallback(call: PluginCall, result: androidx.activity.result.ActivityResult) {
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            doConnect(call)
        } else {
            call.reject("VPN permission denied by user")
        }
    }

    private fun doConnect(call: PluginCall) {
        // Registering with Cloudflare (first run) and bringing the tunnel up both
        // touch the network / disk, so this must not run on the main thread.
        Thread {
            try {
                val configText = getOrCreateWireGuardConfig()
                bringTunnelUpWithEndpointFallback(configText)
                val ret = JSObject()
                ret.put("status", "connected")
                call.resolve(ret)
            } catch (e: Exception) {
                // If nothing worked after trying every known WARP endpoint, the
                // cached identity/endpoint pair may just be a bad match for this
                // network. Drop it so the *next* attempt registers a fresh
                // identity instead of retrying the same dead combination forever.
                prefs().edit().remove(prefsKeyConfig).apply()
                call.reject(describeConnectFailure(e))
            }
        }.start()
    }

    // Cloudflare's WARP relays are reachable on several anycast IPs and ports,
    // not just the single host:port returned at registration time. Networks
    // that block/throttle the default endpoint (common on some Myanmar/Thai
    // ISPs and mobile carriers) often still allow one of the alternates
    // through, so this cycles through them before giving up. This is the same
    // "port hopping" behavior the official WARP client uses.
    private val fallbackWarpEndpoints = listOf(
        "162.159.192.1:2408",
        "162.159.193.10:2408",
        "162.159.195.10:2408",
        "162.159.192.1:500",
        "162.159.192.1:1701",
        "162.159.192.1:4500",
        "162.159.192.1:8854"
    )

    private fun bringTunnelUpWithEndpointFallback(baseConfigText: String) {
        val registeredEndpoint = Regex("(?m)^Endpoint\\s*=\\s*(.+)$")
            .find(baseConfigText)?.groupValues?.get(1)?.trim()

        val candidates = (listOfNotNull(registeredEndpoint) + fallbackWarpEndpoints).distinct()

        var lastError: Exception? = null
        for ((index, endpoint) in candidates.withIndex()) {
            val candidateText = baseConfigText.replaceFirst(
                Regex("(?m)^Endpoint\\s*=.*$"),
                "Endpoint = $endpoint"
            )
            try {
                val config = Config.parse(ByteArrayInputStream(candidateText.toByteArray()))
                // The first candidate (the endpoint Cloudflare actually assigned
                // at registration) gets the full retry treatment since it's the
                // most likely to work. Fallback candidates get one quick try
                // each so cycling through all of them doesn't take minutes.
                if (index == 0) bringTunnelUpWithRetry(config) else backend?.setState(tunnel, Tunnel.State.UP, config)
                return
            } catch (e: Exception) {
                lastError = e
                if (index < candidates.size - 1) sleepBackoff(1)
            }
        }
        throw lastError ?: IOException("Failed to bring tunnel up on any known endpoint")
    }

    // Bringing the WireGuard tunnel up can also fail transiently (e.g. the
    // handshake packet gets dropped once), so it gets the same short retry
    // treatment as the HTTP registration calls below.
    private fun bringTunnelUpWithRetry(config: Config) {
        var lastError: Exception? = null
        for (attempt in 1..maxNetworkAttempts) {
            try {
                backend?.setState(tunnel, Tunnel.State.UP, config)
                return
            } catch (e: Exception) {
                lastError = e
                if (attempt < maxNetworkAttempts) sleepBackoff(attempt)
            }
        }
        throw lastError ?: IOException("Failed to bring tunnel up")
    }

    // Turns a low-level exception into a message that actually tells the user
    // (and whoever reads their bug report) what kind of failure this was,
    // instead of a bare "Connection reset" with no context.
    private fun describeConnectFailure(e: Exception): String {
        val reason = when {
            e is UnknownHostException ->
                "couldn't resolve Cloudflare's server — check DNS / try switching network"
            e is SocketTimeoutException ->
                "connection timed out — the network is slow or dropping packets"
            e.message?.contains("reset", ignoreCase = true) == true ->
                "connection was reset by the network before it completed. This usually " +
                    "means something on the network path (ISP / firewall / captive portal) " +
                    "is blocking WireGuard or Cloudflare's registration endpoint, not a bug " +
                    "in the app. Retried $maxNetworkAttempts times on this network."
            else -> e.message ?: "unknown error"
        }
        return "Failed to connect: $reason"
    }

    @PluginMethod
    fun disconnect(call: PluginCall) {
        try {
            backend?.setState(tunnel, Tunnel.State.DOWN, null)
            val ret = JSObject()
            ret.put("status", "disconnected")
            call.resolve(ret)
        } catch (e: Exception) {
            call.reject("Failed to disconnect: ${e.message}")
        }
    }

    @PluginMethod
    fun getStatus(call: PluginCall) {
        val ret = JSObject()
        ret.put("state", tunnel?.state?.toString() ?: "DOWN")
        call.resolve(ret)
    }

    // ---------------------------------------------------------------------
    // Per-device WARP registration.
    //
    // The previous version of this plugin shipped with ONE WireGuard identity
    // hardcoded into every install of the app. Cloudflare throttles/rejects a
    // single identity once too many devices try to use it at the same time,
    // which is why connections were failing for most people. Each device now
    // registers its own free WARP identity the first time it connects (the
    // same steps generate-warp-config.yml performs), and caches it locally
    // so this only happens once per install.
    // ---------------------------------------------------------------------

    private fun prefs(): SharedPreferences =
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

    private fun getOrCreateWireGuardConfig(): String {
        prefs().getString(prefsKeyConfig, null)?.let { return it }
        val fresh = registerNewWarpIdentity()
        prefs().edit().putString(prefsKeyConfig, fresh).apply()
        return fresh
    }

    private fun registerNewWarpIdentity(): String {
        val keyPair = KeyPair()
        val publicKeyB64 = keyPair.publicKey.toBase64()
        val privateKeyB64 = keyPair.privateKey.toBase64()

        val tosFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        tosFormat.timeZone = TimeZone.getTimeZone("UTC")

        val regBody = JSONObject()
            .put("key", publicKeyB64)
            .put("install_id", "")
            .put("fcm_token", "")
            .put("tos", tosFormat.format(Date()))
            .put("type", "Android")
            .put("locale", "en_US")

        val regJson = httpJsonWithRetry("https://api.cloudflareclient.com/v0a2158/reg", "POST", regBody, null)
        val regId = regJson.getString("id")
        val token = regJson.getString("token")

        // Activate WARP mode for this new identity
        httpJsonWithRetry(
            "https://api.cloudflareclient.com/v0a2158/reg/$regId",
            "PATCH",
            JSONObject().put("warp_enabled", true),
            token
        )

        val addresses = regJson.getJSONObject("config").getJSONObject("interface").getJSONObject("addresses")
        val peer = regJson.getJSONObject("config").getJSONArray("peers").getJSONObject(0)
        val ipv4 = addresses.getString("v4")
        val ipv6 = addresses.getString("v6")
        val peerPublicKey = peer.getString("public_key")
        val endpointHost = peer.getJSONObject("endpoint").getString("host")

        return """
            [Interface]
            PrivateKey = $privateKeyB64
            Address = $ipv4/32, $ipv6/128
            DNS = 1.1.1.1, 2606:4700:4700::1111
            MTU = 1280

            [Peer]
            PublicKey = $peerPublicKey
            Endpoint = $endpointHost
            AllowedIPs = 0.0.0.0/0, ::/0
        """.trimIndent()
    }

    // Retries transient network failures (timeouts, resets, temporary DNS
    // failures) up to maxNetworkAttempts times with a short exponential
    // backoff between tries. Non-transient failures (HTTP 4xx/5xx from
    // Cloudflare itself) are NOT retried since retrying won't change the
    // server's answer.
    private fun httpJsonWithRetry(urlStr: String, method: String, body: JSONObject, bearerToken: String?): JSONObject {
        var lastError: Exception? = null
        for (attempt in 1..maxNetworkAttempts) {
            try {
                return httpJson(urlStr, method, body, bearerToken)
            } catch (e: IOException) {
                lastError = e
                if (attempt < maxNetworkAttempts) sleepBackoff(attempt)
            }
        }
        throw lastError ?: IOException("Network request failed: $urlStr")
    }

    private fun sleepBackoff(attempt: Int) {
        try {
            Thread.sleep(baseBackoffMs * attempt)
        } catch (ignored: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun httpJson(urlStr: String, method: String, body: JSONObject, bearerToken: String?): JSONObject {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        try {
            applyMethod(conn, method)
            conn.doOutput = true
            conn.connectTimeout = 15000
            conn.readTimeout = 15000
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "okhttp/3.12.1")
            if (bearerToken != null) {
                conn.setRequestProperty("Authorization", "Bearer $bearerToken")
            }
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                // HTTP-level rejection from Cloudflare itself — not transient,
                // so this is thrown as a plain Exception (not IOException) so
                // httpJsonWithRetry does not waste time retrying it.
                throw Exception("$method $urlStr failed ($code): $text")
            }
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    // HttpURLConnection only whitelists GET/POST/HEAD/OPTIONS/PUT/DELETE/TRACE,
    // so PATCH has to be forced in via reflection.
    private fun applyMethod(conn: HttpURLConnection, method: String) {
        try {
            conn.requestMethod = method
        } catch (e: java.net.ProtocolException) {
            try {
                val methodField = HttpURLConnection::class.java.getDeclaredField("method")
                methodField.isAccessible = true
                methodField.set(conn, method)
            } catch (ex: Exception) {
                throw e
            }
        }
    }
}
