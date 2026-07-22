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
import java.net.HttpURLConnection
import java.net.URL
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
                val config = Config.parse(ByteArrayInputStream(configText.toByteArray()))
                backend?.setState(tunnel, Tunnel.State.UP, config)
                val ret = JSObject()
                ret.put("status", "connected")
                call.resolve(ret)
            } catch (e: Exception) {
                call.reject("Failed to connect: ${e.message}")
            }
        }.start()
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

        val regJson = httpJson("https://api.cloudflareclient.com/v0a2158/reg", "POST", regBody, null)
        val regId = regJson.getString("id")
        val token = regJson.getString("token")

        // Activate WARP mode for this new identity
        httpJson(
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
    
