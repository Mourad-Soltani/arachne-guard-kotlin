package com.arachne.guard

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Deterministic JSON encoding used for signing and hashing.
 * Matches the Python `canonical()`: sort_keys=True, separators=(",", ":"), ensure_ascii=False.
 *
 * Implementation note: we build a sorted tree then emit compact JSON so the
 * byte sequence is identical across Python and Kotlin for the same logical object.
 */
object Canonical {
    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        isLenient = false
        prettyPrint = false
    }

    fun of(value: Any?): ByteArray {
        return encode(toJsonElement(value)).toByteArray(Charsets.UTF_8)
    }

    private fun toJsonElement(value: Any?): JsonElement = when (value) {
        null -> JsonPrimitive(null as String?)
        is Boolean -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is String -> JsonPrimitive(value)
        is Map<*, *> -> {
            val sorted = value.entries
                .filter { it.key is String }
                .sortedBy { it.key as String }
                .associate { (k, v) -> (k as String) to toJsonElement(v) }
            JsonObject(sorted)
        }
        is Collection<*> -> kotlinx.serialization.json.JsonArray(value.map { toJsonElement(it) })
        is Array<*> -> kotlinx.serialization.json.JsonArray(value.map { toJsonElement(it) })
        else -> JsonPrimitive(value.toString())
    }

    private fun encode(element: JsonElement): String {
        // kotlinx.serialization already produces compact output when prettyPrint=false.
        // Keys in JsonObject are insertion-ordered; we already sorted them above.
        return json.encodeToString(JsonElement.serializer(), element)
    }
}
