package com.arachne.guard

data class Decision(
    val allowed: Boolean,
    val effect: Effect,
    val reason: String,
)

/**
 * Central decision point. Checks, in order:
 * 1. capability string is valid
 * 2. agent card signature verifies
 * 3. card's public key is pinned
 * 4. capability is declared on the card
 * 5. policy (deny > ask > allow, default deny)
 * 6. consent gate for ASK (fails closed)
 *
 * Audit is left as a future port of the Python hash-chain; the skeleton
 * records decisions in a simple list so tests can assert on them.
 */
class Gateway(
    private val trust: TrustStore,
    private val policy: Policy,
    private val consent: (agentId: String, capability: String) -> Boolean = { _, _ -> false },
) {
    val decisions = mutableListOf<Decision>()

    fun authorize(card: AgentCard, capability: String): Decision {
        try {
            validateCapabilityPattern(capability)
        } catch (e: IllegalArgumentException) {
            return record(Decision(false, Effect.DENY, "invalid capability: ${e.message}"))
        }

        if (!verifyCard(card)) {
            return record(Decision(false, Effect.DENY, "card signature invalid"))
        }
        if (card.publicKey == null || !trust.isPinned(card.agentId, card.publicKey)) {
            return record(Decision(false, Effect.DENY, "key not pinned"))
        }
        if (trust.isRevoked(card.agentId)) {
            return record(Decision(false, Effect.DENY, "agent revoked"))
        }
        if (!card.capabilities.any { matches(it, capability) }) {
            return record(Decision(false, Effect.DENY, "capability not declared on card"))
        }

        val effect = policy.decide(capability)
        return when (effect) {
            Effect.DENY -> record(Decision(false, Effect.DENY, "policy denied"))
            Effect.ALLOW -> record(Decision(true, Effect.ALLOW, "allowed"))
            Effect.ASK -> {
                val approved = try {
                    consent(card.agentId, capability)
                } catch (_: Exception) {
                    false
                }
                if (approved) record(Decision(true, Effect.ASK, "consent granted"))
                else record(Decision(false, Effect.ASK, "consent: user denied"))
            }
        }
    }

    private fun record(d: Decision): Decision {
        decisions.add(d)
        return d
    }
}
