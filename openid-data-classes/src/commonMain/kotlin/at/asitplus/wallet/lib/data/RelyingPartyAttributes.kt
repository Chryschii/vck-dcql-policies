package at.asitplus.wallet.lib.data

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Represents attributes identifying which relying parties a disclosure policy applies to.
 * This class wraps a [JsonObject] to allow flexible attribute definitions.
 */
@Serializable(with = RelyingPartyAttributesSerializer::class)
data class RelyingPartyAttributes(
    val attributes: JsonObject
) {
    companion object {
        /**
         * Creates [RelyingPartyAttributes] from a client ID.
         */
        fun fromClientId(clientId: String): RelyingPartyAttributes {
            return RelyingPartyAttributes(
                buildJsonObject {
                    put("client_id", clientId)
                }
            )
        }

        /**
         * Creates [RelyingPartyAttributes] from a client ID and domain.
         */
        fun fromClientIdAndDomain(clientId: String, domain: String): RelyingPartyAttributes {
            return RelyingPartyAttributes(
                buildJsonObject {
                    put("client_id", clientId)
                    put("domain", domain)
                }
            )
        }

        /**
         * Creates [RelyingPartyAttributes] from a map of attributes.
         */
        fun fromMap(attributes: Map<String, String>): RelyingPartyAttributes {
            return RelyingPartyAttributes(
                buildJsonObject {
                    attributes.forEach { (key, value) ->
                        put(key, value)
                    }
                }
            )
        }
    }

    /**
     * Gets an attribute value by key.
     */
    operator fun get(key: String): String? {
        return attributes[key]?.let {
            if (it is kotlinx.serialization.json.JsonPrimitive && it.isString) {
                it.content
            } else null
        }
    }

    /**
     * Checks if an attribute exists.
     */
    fun contains(key: String): Boolean = attributes.containsKey(key)
}

/**
 * Serializer that serializes [RelyingPartyAttributes] as a plain [JsonObject].
 */
object RelyingPartyAttributesSerializer : KSerializer<RelyingPartyAttributes> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun serialize(encoder: Encoder, value: RelyingPartyAttributes) {
        encoder.encodeSerializableValue(JsonObject.serializer(), value.attributes)
    }

    override fun deserialize(decoder: Decoder): RelyingPartyAttributes {
        val jsonObject = decoder.decodeSerializableValue(JsonObject.serializer())
        return RelyingPartyAttributes(jsonObject)
    }
}
