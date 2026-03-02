package at.asitplus.wallet.lib.data

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * A policy-evaluation-scoped snapshot of a relying party's identity, built from
 * an incoming presentation request.
 *
 * It is constructed at presentation time so that every [DisclosurePolicy.relyingPartyQuery]
 * can be matched against it via DCQL, allowing policies to target specific relying parties,
 * client ID schemes, or any other combination of relying party attributes.
 */
data class RelyingPartyContext(
    val attributes: JsonObject,
) {
    val format: CredentialFormatEnum = CredentialFormatEnum.DC_SD_JWT
    val type: String = TYPE
    val claimStructure: DCQLCredentialClaimStructure =
        DCQLCredentialClaimStructure.JsonBasedStructure(attributes)

    operator fun get(key: String): String? =
        (attributes[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    companion object {
        const val TYPE = "RelyingPartyContext"

        /**
         * Builds a [RelyingPartyContext] from a raw [AuthenticationRequestParameters] and its
         * optionally resolved [RelyingPartyMetadata].
         */
        fun fromRequest(
            request: AuthenticationRequestParameters
        ): RelyingPartyContext = RelyingPartyContext(
            buildJsonObject {
                // ------------------------------
                // --- Core request identity ---
                // ------------------------------
                request.clientId?.let { put("client_id", it) }
                request.clientIdSchemeExtracted?.let { put("client_id_scheme", it.stringRepresentation) }
                request.clientIdWithoutPrefix?.let { put("client_id_without_prefix", it) }

                // Response routing
                request.redirectUrl?.let { put("redirect_uri", it) }
                request.redirectUrlExtracted?.let { put("redirect_uri_extracted", it) }
                request.responseUrl?.let { put("response_uri", it) }
                request.responseMode?.let { put("response_mode", it.toString()) }
                request.responseType?.let { put("response_type", it) }

                // Session / transaction
                request.nonce?.let { put("nonce", it) }
                request.state?.let { put("state", it) }
                request.issuer?.let { put("iss", it) }
                request.audience?.let { put("aud", it) }
                request.resource?.let { put("resource", it) }
                request.scope?.let { put("scope", it) }

                // Origins
                request.expectedOrigins?.let { origins ->
                    put("expected_origins", JsonArray(origins.map { JsonPrimitive(it) }))
                }

                // ------------------------------
                // --- Relying party metadata ---
                // ------------------------------
                request.clientMetadata?.let { meta ->
                    meta.clientIdScheme?.let { put("metadata_client_id_scheme", it.toString()) }
                    meta.redirectUris?.let { uris ->
                        put("redirect_uris", JsonArray(uris.map { JsonPrimitive(it) }))
                    }
                    meta.subjectSyntaxTypesSupported?.let { types ->
                        put("subject_syntax_types_supported", JsonArray(types.map { JsonPrimitive(it) }))
                    }
                    meta.vpFormatsSupported?.let { formats ->
                        val formatNames = buildList {
                            if (formats.msoMdoc != null) add(CredentialFormatEnum.MSO_MDOC.toString())
                            if (formats.dcSdJwt != null) add(CredentialFormatEnum.DC_SD_JWT.toString())
                            if (formats.vcJwt != null) add(CredentialFormatEnum.JWT_VC.toString())
                        }
                        if (formatNames.isNotEmpty()) put("vp_formats_supported", JsonArray(formatNames.map { JsonPrimitive(it) }))
                    }
                    meta.idTokenSignedResponseAlgString?.let {
                        put("id_token_signed_response_alg", it)
                    }
                    meta.authorizationSignedResponseAlgString?.let {
                        put("authorization_signed_response_alg", it)
                    }
                    meta.authorizationEncryptedResponseAlgString?.let {
                        put("authorization_encrypted_response_alg", it)
                    }
                    meta.jsonWebKeySetUrl?.let { put("jwks_uri", it) }
                }
            }
        )

        /**
         * Builds a [RelyingPartyContext] from an arbitrary string-keyed attribute map.
         */
        fun fromMap(attributes: Map<String, String>): RelyingPartyContext =
            RelyingPartyContext(
                buildJsonObject { attributes.forEach { (k, v) -> put(k, v) } }
            )
    }
}
