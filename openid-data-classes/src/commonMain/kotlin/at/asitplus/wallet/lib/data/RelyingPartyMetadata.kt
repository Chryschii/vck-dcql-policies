package at.asitplus.wallet.lib.data

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Metadata identifying which relying parties a disclosure policy applies to.
 * This is a flexible JSON structure that can be queried using DCQL.
 */
@Serializable(with = RelyingPartyMetadataSerializer::class)
data class RelyingPartyMetadata(
    val metadata: JsonObject
) {
    companion object {
        /**
         * Creates [RelyingPartyMetadata] from a client ID.
         */
        fun fromClientId(clientId: String): RelyingPartyMetadata {
            return RelyingPartyMetadata(
                buildJsonObject {
                    put("client_id", clientId)
                }
            )
        }

        /**
         * Creates [RelyingPartyMetadata] from a map of attributes.
         */
        fun fromMap(attributes: Map<String, String>): RelyingPartyMetadata {
            return RelyingPartyMetadata(
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
        return metadata[key]?.let {
            if (it is JsonPrimitive && it.isString) {
                it.content
            } else null
        }
    }

    /**
     * Checks if an attribute exists.
     */
    fun contains(key: String): Boolean = metadata.containsKey(key)

    /**
     * Converts this metadata to a pseudo-credential for DCQL querying.
     */
    fun toPseudoCredential(): DisclosurePolicyPseudoCredential {
        return DisclosurePolicyPseudoCredential(this)
    }
}

/**
 * Serializer that serializes [RelyingPartyMetadata] as a plain [JsonObject].
 */
object RelyingPartyMetadataSerializer : KSerializer<RelyingPartyMetadata> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun serialize(encoder: Encoder, value: RelyingPartyMetadata) {
        encoder.encodeSerializableValue(JsonObject.serializer(), value.metadata)
    }

    override fun deserialize(decoder: Decoder): RelyingPartyMetadata {
        val jsonObject = decoder.decodeSerializableValue(JsonObject.serializer())
        return RelyingPartyMetadata(jsonObject)
    }
}

/**
 * Pseudo-credential wrapper for DCQL querying of policy metadata.
 */
data class DisclosurePolicyPseudoCredential(
    val metadata: RelyingPartyMetadata
) {
    val format: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT
    val type: String = "RelyingPartyMetadata"
    val claimStructure: DCQLCredentialClaimStructure =
        DCQLCredentialClaimStructure.JsonBasedStructure(metadata.metadata)
}
