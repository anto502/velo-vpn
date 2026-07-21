package com.anto502.velovpn

import android.net.VpnService
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream

@CapacitorPlugin(name = "VeloVpn")
class VeloVpnPlugin : Plugin() {

    private var backend: GoBackend? = null
    private var tunnel: SimpleTunnel? = null

    private val wgConfigText = """
        [Interface]
        PrivateKey = sNUocN9HmoaQdhznsX4lx7HhH5CpeaW4Axm+W8aTjUQ=
        Address = 172.16.0.2/32, 2606:4700:110:8b83:3654:a1ca:1e55:89e1/128
        DNS = 1.1.1.1

        [Peer]
        PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
        Endpoint = engage.cloudflareclient.com:2408
        AllowedIPs = 0.0.0.0/0, ::/0
    """.trimIndent()

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
        try {
            val config = Config.parse(ByteArrayInputStream(wgConfigText.toByteArray()))
            backend?.setState(tunnel, Tunnel.State.UP, config)
            val ret = JSObject()
            ret.put("status", "connected")
            call.resolve(ret)
        } catch (e: Exception) {
            call.reject("Failed to connect: ${e.message}")
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
}
