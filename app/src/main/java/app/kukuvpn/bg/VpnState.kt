package app.kukuvpn.bg

import app.kukuvpn.data.Profile

/** High-level tunnel state machine (RIX-style). */
enum class TunnelState { OFF, PREPARING, CONNECTING, VERIFYING, ACTIVE, ERROR }

/**
 * Connection stages. A stage lights up only with evidence:
 *  CORE     – the sing-box service started without throwing
 *  LISTENER – the local mixed inbound actually accepts connections
 *  TUNNEL   – a real HTTP request round-tripped through the exit
 *  EXIT     – the exit IP was resolved through the tunnel
 */
enum class TunnelStage { CORE, LISTENER, TUNNEL, EXIT }

data class SessionStats(
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val uptimeSec: Long = 0,
    val connectionsIn: Long = 0,
    val connectionsOut: Long = 0,
)

data class LogLine(
    val time: Long = System.currentTimeMillis(),
    val level: String = "INFO",
    val message: String,
)
