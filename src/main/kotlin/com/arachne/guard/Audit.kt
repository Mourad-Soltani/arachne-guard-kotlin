package com.arachne.guard

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.security.MessageDigest

/**
 * Hash-chained audit log + signed checkpoint.
 * Behavioural port of the Python AuditLog; full persistence is left to the caller.
 */
data class AuditEntry(
    val index: Int,
    val decision: String,
    val agentId: String,
    val capability: String,
    val prevHash: String,
    val hash: String,
)

class AuditLog {
    val entries = mutableListOf<AuditEntry>()

    fun append(decision: String, agentId: String, capability: String): AuditEntry {
        val prev = entries.lastOrNull()?.hash ?: "0".repeat(64)
        val index = entries.size
        val payload = "$index|$decision|$agentId|$capability|$prev"
        val hash = sha256Hex(payload)
        val entry = AuditEntry(index, decision, agentId, capability, prev, hash)
        entries.add(entry)
        return entry
    }

    fun headHash(): String = entries.lastOrNull()?.hash ?: "0".repeat(64)

    fun checkpoint(privateKey: Ed25519PrivateKeyParameters): Map<String, Any> {
        val head = headHash()
        val length = entries.size
        val payload = Canonical.of(mapOf("head" to head, "length" to length))
        val sig = b64(sign(privateKey, payload))
        return mapOf("head" to head, "length" to length, "sig" to sig)
    }

    fun verifyCheckpoint(checkpoint: Map<String, Any>, publicKeyB64: String): Pair<Boolean, String> {
        val head = checkpoint["head"] as? String ?: return false to "malformed"
        val length = (checkpoint["length"] as? Number)?.toInt() ?: return false to "malformed"
        val sig = checkpoint["sig"] as? String ?: return false to "malformed"
        if (length != entries.size || head != headHash()) return false to "checkpoint does not match log"
        return try {
            val pub = Ed25519PublicKeyParameters(unb64(publicKeyB64), 0)
            val payload = Canonical.of(mapOf("head" to head, "length" to length))
            if (verify(pub, unb64(sig), payload)) true to "ok" else false to "bad checkpoint signature"
        } catch (_: Exception) {
            false to "bad checkpoint signature"
        }
    }

    private fun sha256Hex(s: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
