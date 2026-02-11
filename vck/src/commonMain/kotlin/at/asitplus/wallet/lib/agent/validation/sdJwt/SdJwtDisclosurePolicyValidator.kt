package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.data.DisclosurePolicy
import at.asitplus.wallet.lib.data.RelyingPartyAttributes

/**
 * Validates disclosure policies by matching relying party information against policy selectors.
 */
object DisclosurePolicyValidator {

    /**
     * Creates a DCQL selector query to match relying party attributes by ID.
     *
     * @param clientId The relying party's client ID to match
     * @return A DCQL query that can be used to select matching policies
     */
    fun createDisclosurePolicySelectorQuery(clientId: String): DCQLQuery {
        return createDisclosurePolicySelectorQuery(
            DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("rp_selector"),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("RelyingPartyAttributes")
                ),
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(
                            DCQLClaimsPathPointerSegment.NameSegment("client_id")
                        ),
                        values = listOf(
                            DCQLExpectedClaimValue.StringValue(clientId)
                        )
                    )
                )
            )
        )
    }

    /**
     * Creates a DCQL selector query to match relying party attributes.
     *
     * This is a helper to construct a basic query structure. The caller needs to provide the actual
     * claim queries that define what to match on.
     *
     * @param credentialQuery The SD-JWT credential query containing the claims to match
     * @return A DCQL query that can be used to select matching policies
     */
    fun createDisclosurePolicySelectorQuery(
        credentialQuery: DCQLSdJwtCredentialQuery
    ): DCQLQuery {
        return DCQLQuery(
            credentials = DCQLCredentialQueryList(credentialQuery)
        )
    }

    /**
     * Pseudo-credential wrapper for relying party attributes.
     * Used in the validator to apply DCQL queries against stored policy attributes.
     */
    private data class RelyingPartyAttributesCredential(
        val relyingPartyAttributes: RelyingPartyAttributes
    )

    /**
     * Finds the first disclosure policy that matches the provided selector query.
     *
     * @param policies List of disclosure policies embedded in the credential
     * @param selectorQuery DCQL query defining which relying party to match
     * @return The first matching policy, or null if no policy matches
     */
    fun findMatchingPolicy(
        policies: List<DisclosurePolicy>?,
        selectorQuery: DCQLQuery
    ): DisclosurePolicy? {
        if (policies.isNullOrEmpty()) return null

        return policies.firstOrNull { policy ->
            matchesSelector(
                storedAttributes = policy.relyingPartyAttributes,
                selectorQuery = selectorQuery
            ).getOrElse { false }
        }
    }

    /**
     * Finds the first disclosure policy that matches the provided filter.
     *
     * @param policies List of disclosure policies embedded in the credential
     * @param filter The filter to apply for matching
     * @return The first matching policy, or null if no policy matches
     */
    fun findMatchingPolicy(
        policies: List<DisclosurePolicy>?,
        filter: DisclosurePolicyFilter
    ): DisclosurePolicy? {
        if (policies.isNullOrEmpty()) return null

        val selector = DisclosurePolicySelector(policies)
        return selector.selectFirst(filter)
    }

    /**
     * Finds all disclosure policies that match the provided filter.
     *
     * @param policies List of disclosure policies embedded in the credential
     * @param filter The filter to apply for matching
     * @return List of matching policies (may be empty)
     */
    fun findMatchingPolicies(
        policies: List<DisclosurePolicy>?,
        filter: DisclosurePolicyFilter
    ): List<DisclosurePolicy> {
        if (policies.isNullOrEmpty()) return emptyList()

        val selector = DisclosurePolicySelector(policies)
        return selector.select(filter)
    }

    /**
     * Creates a filter for matching policies by client ID.
     *
     * @param clientId The client ID to match
     * @param clientIdKey The attribute key for client ID (default: "client_id")
     * @return A filter that matches policies with the specified client ID
     */
    fun createClientIdFilter(
        clientId: String,
        clientIdKey: String = "client_id"
    ): DisclosurePolicyFilter {
        return AttributeValueFilter(clientIdKey, clientId)
    }

    /**
     * Checks if a selector query matches stored relying party attributes using DCQL.
     */
    private fun matchesSelector(
        storedAttributes: RelyingPartyAttributes,
        selectorQuery: DCQLQuery
    ): KmmResult<Boolean> = catching {
        val pseudoCredential = RelyingPartyAttributesCredential(storedAttributes)

        val result = selectorQuery.execute(
            availableCredentials = listOf(pseudoCredential),
            credentialFormatExtractor = { CredentialFormatEnum.DC_SD_JWT },
            mdocCredentialDoctypeExtractor = { throw IllegalArgumentException("Not an MDOC") },
            sdJwtCredentialTypeExtractor = { "RelyingPartyAttributes" },
            credentialClaimStructureExtractor = {
                DCQLCredentialClaimStructure.JsonBasedStructure(
                    (it as RelyingPartyAttributesCredential).relyingPartyAttributes.attributes
                )
            }
        ).getOrNull()

        result?.credentialQueryMatches?.values?.any { it.isNotEmpty() } ?: false
    }
}
