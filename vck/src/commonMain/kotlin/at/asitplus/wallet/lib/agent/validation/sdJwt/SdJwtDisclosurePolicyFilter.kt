package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.data.DisclosurePolicy

/**
 * Core filter interface for selecting disclosure policies based on custom criteria.
 * Implementations define specific matching logic for different policy attributes.
 */
interface DisclosurePolicyFilter {
    /**
     * Determines if a disclosure policy matches the filter criteria.
     *
     * @param policy The disclosure policy to evaluate
     * @return true if the policy matches, false otherwise
     */
    fun matches(policy: DisclosurePolicy): Boolean
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Composable filter that combines multiple filters using logical operators.
 *
 * @property filters List of filters to combine
 * @property operator Logical operator to apply (AND or OR)
 */
class CompositeDisclosurePolicyFilter(
    private val filters: List<DisclosurePolicyFilter>,
    private val operator: LogicalOperator = LogicalOperator.AND
) : DisclosurePolicyFilter {

    enum class LogicalOperator { AND, OR }

    override fun matches(policy: DisclosurePolicy): Boolean {
        if (filters.isEmpty()) return true

        return when (operator) {
            LogicalOperator.AND -> filters.all { it.matches(policy) }
            LogicalOperator.OR -> filters.any { it.matches(policy) }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Filter that matches policies based on a specific relying party metadata field value using DCQL.
 *
 * @property attributeKey The metadata field key to check (e.g., "client_id", "domain")
 * @property expectedValue The expected value for the field
 */
class AttributeValueFilter(
    private val attributeKey: String,
    private val expectedValue: String
) : DisclosurePolicyFilter {

    private val dcqlQuery = DCQLQuery(
        credentials = DCQLCredentialQueryList(
            DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("rp_filter"),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("RelyingPartyMetadata")
                ),
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(attributeKey),
                        values = listOf(DCQLExpectedClaimValue.StringValue(expectedValue))
                    )
                )
            )
        )
    )

    override fun matches(policy: DisclosurePolicy): Boolean {
        val pseudoCredential = policy.relyingPartyMetadata.toPseudoCredential()

        val result = dcqlQuery.execute(
            availableCredentials = listOf(pseudoCredential),
            credentialFormatExtractor = { it.format },
            mdocCredentialDoctypeExtractor = { "" },
            sdJwtCredentialTypeExtractor = { it.type },
            credentialClaimStructureExtractor = { it.claimStructure }
        ).getOrNull() ?: return false

        return result.credentialQueryMatches.isNotEmpty() &&
                result.credentialQueryMatches.values.any { it.isNotEmpty() }
    }
}

/**
 * Filter that matches policies using a custom predicate function.
 * Uses DCQL to first check if the attribute exists, then applies the predicate.
 *
 * @property attributeKey The metadata field key to evaluate
 * @property predicate Custom function to determine if the field value matches
 */
class AttributePredicateFilter(
    private val attributeKey: String,
    private val predicate: (String?) -> Boolean
) : DisclosurePolicyFilter {

    private val dcqlQuery = DCQLQuery(
        credentials = DCQLCredentialQueryList(
            DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("rp_filter"),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("RelyingPartyMetadata")
                ),
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(attributeKey)
                    )
                )
            )
        )
    )

    override fun matches(policy: DisclosurePolicy): Boolean {
        val pseudoCredential = policy.relyingPartyMetadata.toPseudoCredential()

        // Use DCQL to chekc if the attribute exists
        val result = dcqlQuery.execute(
            availableCredentials = listOf(pseudoCredential),
            credentialFormatExtractor = { it.format },
            mdocCredentialDoctypeExtractor = { "" },
            sdJwtCredentialTypeExtractor = { it.type },
            credentialClaimStructureExtractor = { it.claimStructure }
        ).getOrNull() ?: return predicate(null)

        // If DCQL found matches, the attribute exists
        val hasMatches = result.credentialQueryMatches.isNotEmpty() &&
                result.credentialQueryMatches.values.any { it.isNotEmpty() }

        if (!hasMatches) {
            return predicate(null)
        }

        // Extract the actual value using the RelyingPartyMetadata helper
        val value = policy.relyingPartyMetadata[attributeKey]
        return predicate(value)
    }
}

/**
 * Filter that matches policies where the relying party metadata contains a specific key.
 * Uses DCQL to check for attribute existence.
 *
 * @property attributeKey The metadata field key to check for existence
 */
class AttributeExistsFilter(
    private val attributeKey: String
) : DisclosurePolicyFilter {

    private val dcqlQuery = DCQLQuery(
        credentials = DCQLCredentialQueryList(
            DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("rp_filter"),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("RelyingPartyMetadata")
                ),
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(attributeKey)
                    )
                )
            )
        )
    )

    override fun matches(policy: DisclosurePolicy): Boolean {
        val pseudoCredential = policy.relyingPartyMetadata.toPseudoCredential()

        val result = dcqlQuery.execute(
            availableCredentials = listOf(pseudoCredential),
            credentialFormatExtractor = { it.format },
            mdocCredentialDoctypeExtractor = { "" },
            sdJwtCredentialTypeExtractor = { it.type },
            credentialClaimStructureExtractor = { it.claimStructure }
        ).getOrNull() ?: return false

        return result.credentialQueryMatches.isNotEmpty() &&
                result.credentialQueryMatches.values.any { it.isNotEmpty() }
    }
}

/**
 * Filter that matches policies where a metadata field value is in a set of allowed values.
 * Uses DCQL with multiple expected values.
 *
 * @property attributeKey The metadata field key to check
 * @property allowedValues Set of allowed values
 */
class AttributeInSetFilter(
    private val attributeKey: String,
    private val allowedValues: Set<String>
) : DisclosurePolicyFilter {

    private val dcqlQuery = DCQLQuery(
        credentials = DCQLCredentialQueryList(
            DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("rp_filter"),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("RelyingPartyMetadata")
                ),
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(attributeKey),
                        values = allowedValues.map { DCQLExpectedClaimValue.StringValue(it) }
                    )
                )
            )
        )
    )

    override fun matches(policy: DisclosurePolicy): Boolean {
        val pseudoCredential = policy.relyingPartyMetadata.toPseudoCredential()

        val result = dcqlQuery.execute(
            availableCredentials = listOf(pseudoCredential),
            credentialFormatExtractor = { it.format },
            mdocCredentialDoctypeExtractor = { "" },
            sdJwtCredentialTypeExtractor = { it.type },
            credentialClaimStructureExtractor = { it.claimStructure }
        ).getOrNull() ?: return false

        return result.credentialQueryMatches.isNotEmpty() &&
                result.credentialQueryMatches.values.any { it.isNotEmpty() }
    }
}

/**
 * Filter that always matches all policies (pass-through filter).
 */
object AllPoliciesFilter : DisclosurePolicyFilter {
    override fun matches(policy: DisclosurePolicy): Boolean = true
}

/**
 * Filter that never matches any policy.
 */
object NoPoliciesFilter : DisclosurePolicyFilter {
    override fun matches(policy: DisclosurePolicy): Boolean = false
}
