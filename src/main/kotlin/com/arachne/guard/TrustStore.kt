package com.arachne.guard

/**
 * In-memory pinned-key trust store.
 *
 * Production deployments should persist pins atomically (mode 0600) and support
 * the same rotation/revocation protocol as the Python reference. This skeleton
 * implements the core pin / isPinned / revoke surface so unit tests can run.
 */
class TrustStore {
    private val pins = HashMap<String, String>()          // agentId -> publicKeyB64
    private val revoked = HashSet<String>()

    fun pin(agentId: String, publicKeyB64: String) {
        require(agentId !in revoked) { "agent is revoked" }
        pins[agentId] = publicKeyB64
    }

    fun isPinned(agentId: String, publicKeyB64: String): Boolean {
        if (agentId in revoked) return false
        return pins[agentId] == publicKeyB64
    }

    fun revoke(agentId: String) {
        pins.remove(agentId)
        revoked.add(agentId)
    }

    fun isRevoked(agentId: String): Boolean = agentId in revoked
}
