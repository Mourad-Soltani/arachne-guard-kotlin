package com.arachne.guard

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import java.util.Base64

/**
 * Agent identity: Ed25519-signed agent cards and a pinned-key trust store.
 *
 * A card that merely *contains* a signature proves nothing. [verifyCard]
 * checks the signature cryptographically over the canonical JSON of every
 * field except the signature, and [TrustStore] pins which public key is
 * allowed to speak for which agent id.
 */

fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
fun unb64(text: String): ByteArray = Base64.getDecoder().decode(text)

data class KeyPair(
    val private: Ed25519PrivateKeyParameters,
    val public: Ed25519PublicKeyParameters,
) {
    val publicKeyB64: String get() = b64(public.encoded)
}

fun generateKeypair(random: SecureRandom = SecureRandom()): KeyPair {
    val priv = Ed25519PrivateKeyParameters(random)
    return KeyPair(priv, priv.generatePublicKey())
}

data class AgentCard(
    val agentId: String,
    val name: String,
    val version: String,
    val description: String = "",
    val capabilities: Set<String> = emptySet(),
    val endpoint: String? = null,
    val publicKey: String? = null,
    val signature: String? = null,
    val metadata: Map<String, String> = emptyMap(),
) {
    init {
        require(agentId.isNotBlank()) { "agent_id must not be blank" }
        capabilities.forEach { validateCapabilityPattern(it) }
    }

    fun signingPayload(): ByteArray {
        val body = linkedMapOf<String, Any?>(
            "agent_id" to agentId,
            "name" to name,
            "version" to version,
            "description" to description,
            "capabilities" to capabilities.sorted(),
            "endpoint" to endpoint,
            "public_key" to publicKey,
            "metadata" to metadata.toSortedMap(),
        )
        return Canonical.of(body)
    }

    fun toMap(): Map<String, Any?> = mapOf(
        "agent_id" to agentId,
        "name" to name,
        "version" to version,
        "description" to description,
        "capabilities" to capabilities.sorted(),
        "endpoint" to endpoint,
        "public_key" to publicKey,
        "signature" to signature,
        "metadata" to metadata,
    )

    companion object {
        fun fromMap(data: Map<String, Any?>): AgentCard {
            @Suppress("UNCHECKED_CAST")
            val caps = (data["capabilities"] as? Collection<*>)?.map { it.toString() }?.toSet() ?: emptySet()
            @Suppress("UNCHECKED_CAST")
            val meta = (data["metadata"] as? Map<*, *>)?.entries
                ?.associate { it.key.toString() to it.value.toString() } ?: emptyMap()
            return AgentCard(
                agentId = data["agent_id"] as String,
                name = data["name"] as String,
                version = data["version"] as String,
                description = data["description"] as? String ?: "",
                capabilities = caps,
                endpoint = data["endpoint"] as? String,
                publicKey = data["public_key"] as? String,
                signature = data["signature"] as? String,
                metadata = meta,
            )
        }
    }
}

fun signCard(card: AgentCard, keyPair: KeyPair): AgentCard {
    val withKey = card.copy(publicKey = keyPair.publicKeyB64, signature = null)
    val sig = sign(keyPair.private, withKey.signingPayload())
    return withKey.copy(signature = b64(sig))
}

fun verifyCard(card: AgentCard): Boolean {
    if (card.signature == null || card.publicKey == null) return false
    return try {
        val pub = Ed25519PublicKeyParameters(unb64(card.publicKey), 0)
        verify(pub, unb64(card.signature), card.signingPayload())
    } catch (_: Exception) {
        false
    }
}

internal fun sign(private: Ed25519PrivateKeyParameters, message: ByteArray): ByteArray {
    val signer = Ed25519Signer()
    signer.init(true, private)
    signer.update(message, 0, message.size)
    return signer.generateSignature()
}

internal fun verify(public: Ed25519PublicKeyParameters, signature: ByteArray, message: ByteArray): Boolean {
    val verifier = Ed25519Signer()
    verifier.init(false, public)
    verifier.update(message, 0, message.size)
    return verifier.verifySignature(signature)
}

/** Minimal capability-pattern validation (mirrors Python `validate_pattern`). */
fun validateCapabilityPattern(pattern: String) {
    require(pattern.isNotBlank()) { "capability must not be blank" }
    // Keep the same basic rules as the Python side for cross-port tests.
    require(!pattern.contains("..")) { "capability must not contain '..'" }
}
