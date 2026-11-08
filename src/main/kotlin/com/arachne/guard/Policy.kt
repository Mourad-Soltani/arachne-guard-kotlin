package com.arachne.guard

enum class Effect { ALLOW, DENY, ASK }

data class Rule(
    val effect: Effect,
    val capability: String,
)

/**
 * Default-deny policy. Evaluation order: deny > ask > allow.
 * First matching rule of the highest-priority effect wins.
 */
class Policy(private val rules: List<Rule>) {
    fun decide(capability: String): Effect {
        var sawAsk = false
        var sawAllow = false
        for (rule in rules) {
            if (!matches(rule.capability, capability)) continue
            when (rule.effect) {
                Effect.DENY -> return Effect.DENY
                Effect.ASK -> sawAsk = true
                Effect.ALLOW -> sawAllow = true
            }
        }
        return when {
            sawAsk -> Effect.ASK
            sawAllow -> Effect.ALLOW
            else -> Effect.DENY
        }
    }

    companion object {
        fun fromMap(data: Map<String, Any?>): Policy {
            @Suppress("UNCHECKED_CAST")
            val rawRules = data["rules"] as? List<Map<String, Any?>> ?: emptyList()
            val rules = rawRules.map { r ->
                val effect = when ((r["effect"] as String).lowercase()) {
                    "allow" -> Effect.ALLOW
                    "deny" -> Effect.DENY
                    "ask" -> Effect.ASK
                    else -> error("unknown effect: ${r["effect"]}")
                }
                Rule(effect, r["capability"] as String)
            }
            return Policy(rules)
        }
    }
}

/** Simple capability matcher: exact or trailing `*` wildcard. */
fun matches(pattern: String, capability: String): Boolean {
    if (pattern == capability) return true
    if (pattern.endsWith("*")) {
        val prefix = pattern.dropLast(1)
        return capability.startsWith(prefix)
    }
    return false
}
