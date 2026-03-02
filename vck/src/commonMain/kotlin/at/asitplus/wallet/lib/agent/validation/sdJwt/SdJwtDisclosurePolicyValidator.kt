package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.data.DisclosurePolicy
import at.asitplus.wallet.lib.data.RelyingPartyContext

/**
 * Matches an incoming [RelyingPartyContext] against embedded [DisclosurePolicy] entries
 * using DCQL, and determines which policies are applicable to the current request.
 */
object DisclosurePolicyValidator {

    /**
     * Runs [relyingPartyQuery] against [relyingPartyContext] and returns true when the query
     * produces at least one match — meaning this policy is applicable to the current request.
     */
    private fun matches(
        relyingPartyQuery: DCQLQuery,
        relyingPartyContext: RelyingPartyContext,
    ): Boolean {
        val result = relyingPartyQuery.execute(
            availableCredentials = listOf(relyingPartyContext),
            credentialFormatExtractor = { it.format },
            mdocCredentialDoctypeExtractor = { "" },
            sdJwtCredentialTypeExtractor = { it.type },
            credentialClaimStructureExtractor = { it.claimStructure },
        ).getOrNull() ?: return false

        return result.credentialQueryMatches.values.any { it.isNotEmpty() }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Returns every [DisclosurePolicy] whose [DisclosurePolicy.relyingPartyQuery] matches
     * the given [relyingPartyContext].
     */
    fun findApplicablePolicies(
        policies: List<DisclosurePolicy>?,
        relyingPartyContext: RelyingPartyContext,
    ): List<DisclosurePolicy> {
        if (policies.isNullOrEmpty()) return emptyList()
        return policies.filter { policy ->
            matches(policy.relyingPartyQuery, relyingPartyContext)
        }
    }
}
