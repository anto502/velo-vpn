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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
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

    // Direct IPs for api.cloudflareclient.com — used as a fallback when DNS
    // resolution of the domain itself fails, since some networks/countries
    // block that specific domain (documented behavior, e.g. in Russia) while
    // leaving the underlying Cloudflare IPs reachable.
    private val knownWarpApiIps = listOf(
        "188.114.98.128",
        "188.114.99.128"
    )

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
                // NOTE: we deliberately do NOT discard the cached identity here
                // anymore. Registration is the most fragile/censorable network
                // path (some networks specifically block Cloudflare's WARP
                // registration API by domain), so a tunnel-connect failure that
                // has nothing to do with the identity itself should not force
                // every subsequent attempt to redo that fragile registration.
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
    fun connectTor(call: PluginCall) {
        // Only one system VPN interface can be active at a time, so drop the
        // WireGuard/WARP tunnel first if it's up.
        try { backend?.setState(tunnel, Tunnel.State.DOWN, null) } catch (ignored: Exception) {}

        val svcIntent = android.content.Intent(context, TorEngineService::class.java)
        svcIntent.action = TorEngineService.ACTION_START
        androidx.core.content.ContextCompat.startForegroundService(context, svcIntent)
        val ret = JSObject()
        // Tor bootstrap happens asynchronously inside TorEngineService (can take
        // 10-60s); poll getTorStatus() to see when it's actually ready.
        ret.put("status", "connecting")
        call.resolve(ret)
    }

    @PluginMethod
    fun disconnectTor(call: PluginCall) {
        val svcIntent = android.content.Intent(context, TorEngineService::class.java)
        svcIntent.action = TorEngineService.ACTION_STOP
        context.startService(svcIntent)
        val ret = JSObject()
        ret.put("status", "disconnected")
        call.resolve(ret)
    }

    @PluginMethod
    fun getTorStatus(call: PluginCall) {
        val ret = JSObject()
        ret.put("bootstrapped", TorEngineService.isBootstrapped)
        ret.put("socksPort", TorEngineService.socksPort)
        call.resolve(ret)
    }

    // ---------------------------------------------------------------------
    // VPNGate (OpenVPN, via the ics-openvpn library) — an alternative to the
    // Cloudflare WARP path above, for networks where WARP's registration API
    // itself is blocked. VPNGate servers are run by volunteers (an academic
    // project, University of Tsukuba), reachable via a public CSV list.
    //
    // NOTE: ics-openvpn is normally embedded as a full app, not consumed as a
    // clean library, so the exact entry points here (ConfigParser,
    // ProfileManager, VPNLaunchHelper, OpenVPNService) are the most likely
    // spot for a "unresolved reference" on first build — if that happens,
    // the CI error will tell us which specific symbol needs adjusting.
    // ---------------------------------------------------------------------

    @PluginMethod
    fun fetchVpnGateServers(call: PluginCall) {
        Thread {
            try {
                val csvText = fetchVpnGateCsv()
                val servers = parseVpnGateCsv(csvText)
                val ret = JSObject()
                val arr = org.json.JSONArray()
                for (s in servers) arr.put(s)
                ret.put("servers", arr)
                call.resolve(ret)
            } catch (e: Exception) {
                call.reject("Failed to fetch VPNGate server list: ${e.message}")
            }
        }.start()
    }

    private fun fetchVpnGateCsv(): String {
        val conn = URL("https://www.vpngate.net/api/iphone/").openConnection() as HttpURLConnection
        conn.connectTimeout = 15000
        conn.readTimeout = 15000
        try {
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    // VPNGate's CSV: a couple of comment lines, then a header row, then one
    // row per server. Fields are comma-separated; the last field
    // (OpenVPN_ConfigData_Base64) can itself legitimately be a long base64
    // blob with no commas, so simple split-by-comma is safe here.
    private fun parseVpnGateCsv(csv: String): List<JSONObject> {
        val lines = csv.lines().filter { it.isNotBlank() && !it.startsWith("*") && !it.startsWith("#") }
        val out = mutableListOf<JSONObject>()
        for (line in lines) {
            val cols = line.split(",")
            if (cols.size < 15) continue
            try {
                val obj = JSONObject()
                obj.put("hostName", cols[0])
                obj.put("ip", cols[1])
                obj.put("score", cols[2].toLongOrNull() ?: 0)
                obj.put("pingMs", cols[3].toIntOrNull() ?: -1)
                obj.put("speedBps", cols[4].toLongOrNull() ?: 0)
                obj.put("countryLong", cols[5])
                obj.put("countryShort", cols[6])
                obj.put("sessions", cols[7].toIntOrNull() ?: 0)
                obj.put("ovpnConfigBase64", cols[14])
                out.add(obj)
            } catch (ignored: Exception) {
                // Skip malformed rows rather than failing the whole list.
            }
        }
        // Best servers (highest score = combination of speed/uptime/ping) first.
        return out.sortedByDescending { it.getLong("score") }
    }

    @PluginMethod
    fun connectVpnGate(call: PluginCall) {
        val configBase64 = call.getString("ovpnConfigBase64")
        if (configBase64.isNullOrBlank()) {
            call.reject("ovpnConfigBase64 is required")
            return
        }
        val intent = VpnService.prepare(context)
        if (intent != null) {
            savedVpnGateCall = call
            savedVpnGateConfigBase64 = configBase64
            startActivityForResult(call, intent, "vpnGatePermissionCallback")
            return
        }
        doConnectVpnGate(call, configBase64)
    }

    private var savedVpnGateCall: PluginCall? = null
    private var savedVpnGateConfigBase64: String? = null

    @com.getcapacitor.annotation.ActivityCallback
    private fun vpnGatePermissionCallback(call: PluginCall, result: androidx.activity.result.ActivityResult) {
        val configBase64 = savedVpnGateConfigBase64
        savedVpnGateConfigBase64 = null
        if (result.resultCode == android.app.Activity.RESULT_OK && configBase64 != null) {
            doConnectVpnGate(call, configBase64)
        } else {
            call.reject("VPN permission denied by user")
        }
    }

    private fun doConnectVpnGate(call: PluginCall, configBase64: String) {
        // Drop the WireGuard/WARP tunnel first — only one VPN interface can
        // be active at a time.
        try { backend?.setState(tunnel, Tunnel.State.DOWN, null) } catch (ignored: Exception) {}

        Thread {
            try {
                val ovpnText = String(android.util.Base64.decode(configBase64, android.util.Base64.DEFAULT), Charsets.UTF_8)
                val parser = de.blinkt.openvpn.core.ConfigParser()
                parser.parseConfig(java.io.StringReader(ovpnText))
                val profile = parser.convertProfile()
                profile.mName = "VPNGate"
                de.blinkt.openvpn.core.ProfileManager.setTemporaryProfile(context, profile)
                de.blinkt.openvpn.core.VPNLaunchHelper.startOpenVpn(profile, context)

                val ret = JSObject()
                ret.put("status", "connecting")
                call.resolve(ret)
            } catch (e: Exception) {
                call.reject("Failed to connect via VPNGate: ${e.message}")
            }
        }.start()
    }

    @PluginMethod
    fun disconnectVpnGate(call: PluginCall) {
        try {
            val intent = android.content.Intent(context, de.blinkt.openvpn.core.OpenVPNService::class.java)
            intent.action = de.blinkt.openvpn.core.OpenVPNService.START_SERVICE
            val connection = object : android.content.ServiceConnection {
                override fun onServiceConnected(name: android.content.ComponentName?, binder: android.os.IBinder?) {
                    try {
                        val svc = binder as? de.blinkt.openvpn.core.OpenVPNService
                        svc?.stopVPN(false)
                    } catch (ignored: Exception) {}
                    try { context.unbindService(this) } catch (ignored: Exception) {}
                }
                override fun onServiceDisconnected(name: android.content.ComponentName?) {}
            }
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
            val ret = JSObject()
            ret.put("status", "disconnected")
            call.resolve(ret)
        } catch (e: Exception) {
            call.reject("Failed to disconnect VPNGate: ${e.message}")
        }
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
        prefs().getString(prefsKeyConfig, null)?.let { cached ->
            var patched = cached

            // Strip IPv6 in place — keep the SAME already-registered identity
            // and endpoint (which was already handshaking fine) rather than
            // discarding it and forcing a brand new registration network call.
            // Forcing re-registration here was the actual regression: it made
            // every connect depend on reaching Cloudflare's REST API, which is
            // a separate, less reliable network path than the WireGuard UDP
            // tunnel itself.
            patched = Regex("""(?m)^Address\s*=\s*([^,\n]+),\s*[^\n]+$""")
                .replace(patched) { "Address = ${it.groupValues[1].trim()}" }
            patched = Regex("""(?m)^DNS\s*=\s*([^,\n]+),\s*[^\n]+$""")
                .replace(patched) { "DNS = ${it.groupValues[1].trim()}" }
            patched = Regex("""(?m)^AllowedIPs\s*=\s*([^,\n]+),\s*[^\n]+$""")
                .replace(patched) { "AllowedIPs = ${it.groupValues[1].trim()}" }
            if (!patched.contains("PersistentKeepalive")) {
                patched = patched.trimEnd() + "\nPersistentKeepalive = 25\n"
            }
            if (patched != cached) {
                prefs().edit().putString(prefsKeyConfig, patched).apply()
            }
            return patched
        }
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
        val peerPublicKey = peer.getString("public_key")
        val endpointHost = peer.getJSONObject("endpoint").getString("host")

        // IPv4-only on purpose: many mobile carrier networks (common in
        // Myanmar) have broken/partial IPv6 support. Forcing ::/0 through the
        // tunnel on such a network silently blackholes IPv6-preferred traffic
        // — the tunnel still reports "connected" but nothing actually loads.
        return """
            [Interface]
            PrivateKey = $privateKeyB64
            Address = $ipv4/32
            DNS = 1.1.1.1
            MTU = 1280

            [Peer]
            PublicKey = $peerPublicKey
            Endpoint = $endpointHost
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 25
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
        val url = URL(urlStr)
        try {
            return httpJsonViaUrl(url, method, body, bearerToken)
        } catch (e: UnknownHostException) {
            // api.cloudflareclient.com's DOMAIN can be blocked at the DNS
            // level by some ISPs/countries (this is a documented, known thing
            // — e.g. Roscomnadzor does exactly this in Russia) even though
            // Cloudflare's IPs themselves are reachable. Retry by connecting
            // directly to a known WARP registration IP while keeping the
            // hostname for SNI/Host/certificate validation, which routes
            // around DNS-level blocking specifically.
            for (ip in knownWarpApiIps) {
                try {
                    return httpJsonViaDirectIp(ip, url, method, body, bearerToken)
                } catch (inner: Exception) {
                    // try next candidate IP
                }
            }
            throw e
        }
    }

    private fun httpJsonViaUrl(url: URL, method: String, body: JSONObject, bearerToken: String?): JSONObject {
        val conn = url.openConnection() as HttpURLConnection
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
                throw Exception("$method $url failed ($code): $text")
            }
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    // Connects to a raw IP address for the TCP/TLS layer (routing around DNS
    // censorship of the hostname) while still presenting the real hostname
    // for SNI/Host header/certificate validation, so the TLS handshake and
    // Cloudflare's own routing both still work correctly.
    private fun httpJsonViaDirectIp(ip: String, url: URL, method: String, body: JSONObject, bearerToken: String?): JSONObject {
        val host = url.host
        val port = if (url.port != -1) url.port else 443
        val rawSocket = Socket()
        rawSocket.connect(InetSocketAddress(InetAddress.getByName(ip), port), 15000)
        rawSocket.soTimeout = 15000
        val sslSocket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
            .createSocket(rawSocket, host, port, true) as SSLSocket
        sslSocket.startHandshake()

        val bodyBytes = body.toString().toByteArray(Charsets.UTF_8)
        val requestLines = StringBuilder()
        requestLines.append("$method ${url.path}${if (url.query != null) "?${url.query}" else ""} HTTP/1.1\r\n")
        requestLines.append("Host: $host\r\n")
        requestLines.append("Content-Type: application/json\r\n")
        requestLines.append("Content-Length: ${bodyBytes.size}\r\n")
        requestLines.append("User-Agent: okhttp/3.12.1\r\n")
        if (bearerToken != null) requestLines.append("Authorization: Bearer $bearerToken\r\n")
        requestLines.append("Connection: close\r\n\r\n")

        sslSocket.outputStream.write(requestLines.toString().toByteArray(Charsets.UTF_8))
        sslSocket.outputStream.write(bodyBytes)
        sslSocket.outputStream.flush()

        val rawResponse = sslSocket.inputStream.bufferedReader().use { it.readText() }
        sslSocket.close()

        val headerEnd = rawResponse.indexOf("\r\n\r\n")
        val headerPart = if (headerEnd >= 0) rawResponse.substring(0, headerEnd) else rawResponse
        val statusLine = headerPart.lineSequence().firstOrNull() ?: ""
        val code = Regex("""HTTP/1\.[01]\s+(\d+)""").find(statusLine)?.groupValues?.get(1)?.toIntOrNull() ?: -1
        var text = if (headerEnd >= 0) rawResponse.substring(headerEnd + 4) else ""

        // Undo chunked transfer-encoding if present (Cloudflare may use it).
        if (headerPart.contains("Transfer-Encoding: chunked", ignoreCase = true)) {
            text = dechunk(text)
        }

        if (code !in 200..299) {
            throw Exception("$method $url failed ($code) via direct IP $ip: $text")
        }
        return JSONObject(text)
    }

    private fun dechunk(chunked: String): String {
        val out = StringBuilder()
        var idx = 0
        while (idx < chunked.length) {
            val lineEnd = chunked.indexOf("\r\n", idx)
            if (lineEnd < 0) break
            val sizeHex = chunked.substring(idx, lineEnd).trim()
            val size = sizeHex.toIntOrNull(16) ?: break
            if (size == 0) break
            val chunkStart = lineEnd + 2
            val chunkEnd = (chunkStart + size).coerceAtMost(chunked.length)
            out.append(chunked, chunkStart, chunkEnd)
            idx = chunkEnd + 2
        }
        return out.toString()
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
