package com.arachne.guard

import java.util.PriorityQueue

/**
 * Replay protection: bounded nonce cache with a clock-skew window.
 *
 * A nonce is remembered until `ts + window`. After that the timestamp check
 * alone rejects any replay. The cache is bounded and fails closed when full.
 */
class ReplayGuard(
    private val windowSeconds: Double = 60.0,
    private val maxEntries: Int = 10_000,
    private val clock: () -> Double = { System.currentTimeMillis() / 1000.0 },
) {
    init {
        require(windowSeconds > 0) { "window_seconds must be > 0" }
        require(maxEntries >= 1) { "max_entries >= 1" }
    }

    private val seen = HashMap<Pair<String, String>, Double>()
    private val heap = PriorityQueue<Pair<Double, Pair<String, String>>>(compareBy { it.first })

    fun check(agentId: String, nonce: Any?, ts: Any?): Pair<Boolean, String> {
        if (nonce !is String || nonce.length !in 8..128) {
            return false to "nonce must be a string of 8 to 128 characters"
        }
        if (ts is Boolean || ts !is Number) {
            return false to "timestamp must be a number"
        }
        val tsVal = ts.toDouble()
        val now = clock()
        if (kotlin.math.abs(now - tsVal) > windowSeconds) {
            return false to "timestamp outside allowed window"
        }
        evict(now)
        val key = agentId to nonce
        if (key in seen) return false to "replayed nonce"
        if (seen.size >= maxEntries) return false to "replay cache full"
        val expiry = tsVal + windowSeconds
        seen[key] = expiry
        heap.add(expiry to key)
        return true to "ok"
    }

    private fun evict(now: Double) {
        while (heap.isNotEmpty() && heap.peek().first < now) {
            val (expiry, key) = heap.poll()
            if (seen[key] == expiry) {
                seen.remove(key)
            }
        }
    }

    val size: Int get() = seen.size
}
