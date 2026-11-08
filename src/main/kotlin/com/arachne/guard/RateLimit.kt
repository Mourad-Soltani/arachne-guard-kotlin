package com.arachne.guard

/**
 * Simple per-agent sliding-window rate limiter.
 * Matches the Python RateLimiter behaviour for cross-port tests.
 */
class RateLimiter(
    private val maxRequests: Int,
    private val windowSeconds: Double,
    private val clock: () -> Double = { System.currentTimeMillis() / 1000.0 },
) {
    private val hits = HashMap<String, MutableList<Double>>()

    fun allow(agentId: String): Boolean {
        val now = clock()
        val list = hits.getOrPut(agentId) { mutableListOf() }
        list.removeAll { it < now - windowSeconds }
        if (list.size >= maxRequests) return false
        list.add(now)
        return true
    }
}
