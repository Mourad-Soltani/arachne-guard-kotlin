package com.arachne.guard

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Signed requests: proof that the caller holds the agent's private key.
 *
 * A public agent card alone must not let anyone act as the agent. The agent
 * signs the canonical form of (agent id, jsonrpc, id, method, params, nonce, ts)
 * and attaches it as `auth`. Verification uses the key embedded in the card,
 * which the gateway separately requires to be pinned.
 */

private fun payload(agentId: String, request: Map<String, Any?>, nonce: String, ts: Double): ByteArray {
    return Canonical.of(
        mapOf(
            "agent_id" to agentId,
            "jsonrpc" to request["jsonrpc"],
            "id" to request["id"],
            "method" to request["method"],
            "params" to request["params"],
            "nonce" to nonce,
            "ts" to ts,
        )
    )
}

fun signRequest(
    privateKey: Ed25519PrivateKeyParameters,
    agentId: String,
    request: Map<String, Any?>,
    nonce: String? = null,
    ts: Double? = null,
    random: SecureRandom = SecureRandom(),
): Map<String, Any?> {
    val n = nonce ?: random.generateSeed(16).joinToString("") { "%02x".format(it) }
    val t = ts ?: (System.currentTimeMillis() / 1000.0)
    val sig = b64(sign(privateKey, payload(agentId, request, n, t)))
    val auth = mapOf("nonce" to n, "ts" to t, "sig" to sig)
    return request + ("auth" to auth)
}

/**
 * Returns (ok, reason). Matches Python `verify_request` behaviour, including
 * the rejection of boolean timestamps (a common JSON quirk).
 */
fun verifyRequest(card: AgentCard, request: Map<String, Any?>): Pair<Boolean, String> {
    val auth = request["auth"] as? Map<*, *> ?: return false to "missing auth"
    if (card.publicKey == null) return false to "missing auth"

    val nonce = auth["nonce"]
    val ts = auth["ts"]
    val sig = auth["sig"]

    if (nonce !is String) return false to "malformed auth"
    // Explicitly reject Boolean (JSON true/false) before number check.
    if (ts is Boolean || (ts !is Number)) return false to "malformed auth"
    if (sig !is String) return false to "malformed auth"

    return try {
        val pub = Ed25519PublicKeyParameters(unb64(card.publicKey), 0)
        val ok = verify(pub, unb64(sig), payload(card.agentId, request, nonce, ts.toDouble()))
        if (ok) true to "ok" else false to "bad request signature"
    } catch (_: Exception) {
        false to "bad request signature"
    }
}
