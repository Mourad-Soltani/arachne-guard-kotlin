package com.arachne.guard

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Behavioural test vectors that must match the Python reference (0.4.0).
 * These are the checks a Kotlin/Android port is expected to pass.
 */
class SecurityVectorsTest {

    @Test
    fun cardRoundTripAndVerify() {
        val kp = generateKeypair()
        val card = signCard(
            AgentCard(
                agentId = "trip-agent",
                name = "Trip",
                version = "1",
                capabilities = setOf("mcp.call:*"),
            ),
            kp,
        )
        assertTrue(verifyCard(card))
        assertEquals(kp.publicKeyB64, card.publicKey)

        // Tamper
        val bad = card.copy(name = "Evil")
        assertFalse(verifyCard(bad))
    }

    @Test
    fun requestSignatureBindsFields() {
        val kp = generateKeypair()
        val card = signCard(
            AgentCard("agent-1", "A", "1", capabilities = setOf("mcp.call:weather")),
            kp,
        )
        val request = mapOf(
            "jsonrpc" to "2.0",
            "id" to 1,
            "method" to "tools/call",
            "params" to mapOf("name" to "weather", "arguments" to mapOf("city" to "Tunis")),
        )
        val signed = signRequest(kp.private, card.agentId, request)
        val (ok, reason) = verifyRequest(card, signed)
        assertTrue(ok, reason)

        // Wrong agent id in payload path: change card
        val other = signCard(AgentCard("other", "O", "1", capabilities = setOf("mcp.call:*")), generateKeypair())
        val (ok2, _) = verifyRequest(other, signed)
        assertFalse(ok2)
    }

    @Test
    fun booleanTimestampRejected() {
        val kp = generateKeypair()
        val card = signCard(AgentCard("a", "A", "1", capabilities = setOf("x")), kp)
        val request = mapOf(
            "jsonrpc" to "2.0",
            "id" to 1,
            "method" to "tools/list",
            "params" to emptyMap<String, Any>(),
            "auth" to mapOf(
                "nonce" to "abcdef0123456789",
                "ts" to true,          // JSON boolean — must be rejected
                "sig" to "not-checked",
            ),
        )
        val (ok, reason) = verifyRequest(card, request)
        assertFalse(ok)
        assertEquals("malformed auth", reason)
    }

    @Test
    fun replayGuardRejectsReuseAndBadTypes() {
        val guard = ReplayGuard(windowSeconds = 60.0, maxEntries = 10)
        val (ok1, _) = guard.check("agent", "nonce-abc-12345", 1_700_000_000.0)
        assertTrue(ok1)
        val (ok2, reason) = guard.check("agent", "nonce-abc-12345", 1_700_000_000.0)
        assertFalse(ok2)
        assertEquals("replayed nonce", reason)

        val (ok3, r3) = guard.check("agent", true, 1_700_000_000.0)
        assertFalse(ok3)
        assertTrue(r3.contains("nonce"))

        val (ok4, r4) = guard.check("agent", "nonce-xyz-12345", true)
        assertFalse(ok4)
        assertEquals("timestamp must be a number", r4)
    }

    @Test
    fun policyDenyOverridesAllow() {
        val policy = Policy.fromMap(
            mapOf(
                "rules" to listOf(
                    mapOf("effect" to "allow", "capability" to "mcp.call:*"),
                    mapOf("effect" to "deny", "capability" to "mcp.call:delete_all"),
                )
            )
        )
        assertEquals(Effect.DENY, policy.decide("mcp.call:delete_all"))
        assertEquals(Effect.ALLOW, policy.decide("mcp.call:weather"))
        assertEquals(Effect.DENY, policy.decide("other.thing"))
    }

    @Test
    fun gatewayRequiresPinAndConsentFailsClosed() {
        val kp = generateKeypair()
        val card = signCard(
            AgentCard("trip", "Trip", "1", capabilities = setOf("mcp.call:*")),
            kp,
        )
        val trust = TrustStore()
        trust.pin(card.agentId, card.publicKey!!)
        val policy = Policy.fromMap(
            mapOf(
                "rules" to listOf(
                    mapOf("effect" to "allow", "capability" to "mcp.call:weather"),
                    mapOf("effect" to "ask", "capability" to "mcp.call:read_contacts"),
                )
            )
        )
        val gw = Gateway(trust, policy) { _, _ -> false }  // always deny consent

        val d1 = gw.authorize(card, "mcp.call:weather")
        assertTrue(d1.allowed)

        val d2 = gw.authorize(card, "mcp.call:read_contacts")
        assertFalse(d2.allowed)
        assertTrue(d2.reason.contains("consent"))

        val d3 = gw.authorize(card, "mcp.call:delete_all")
        assertFalse(d3.allowed)
    }

    @Test
    fun unpinnedCardRejected() {
        val kp = generateKeypair()
        val card = signCard(AgentCard("x", "X", "1", capabilities = setOf("mcp.call:*")), kp)
        val trust = TrustStore()
        // deliberately not pinned
        val gw = Gateway(trust, Policy(emptyList()))
        val d = gw.authorize(card, "mcp.call:weather")
        assertFalse(d.allowed)
        assertTrue(d.reason.contains("pin") || d.reason.contains("pinned"))
    }
}
