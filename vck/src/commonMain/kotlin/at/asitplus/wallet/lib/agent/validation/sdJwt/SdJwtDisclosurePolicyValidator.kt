package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
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

    /**
     * Extracts a set of [DCQLClaimsPathPointer]s from a [DCQLCredentialQueryMatchingResult].
     */
    private fun extractClaimPaths(
        result: DCQLCredentialQueryMatchingResult?
    ): Set<DCQLClaimsPathPointer> {
        val claimPaths = (result as? DCQLCredentialQueryMatchingResult.ClaimsQueryResults)
            ?.claimsQueryResults
            ?.filterIsInstance<DCQLClaimsQueryResult.JsonResult>()
            ?.flatMap { it.nodeList }
            ?.mapNotNull { entry ->
                val segments: List<DCQLClaimsPathPointerSegment> =
                    entry.normalizedJsonPath.segments.map { segment ->
                        when (segment) {
                            is NormalizedJsonPathSegment.NameSegment ->
                                DCQLClaimsPathPointerSegment.NameSegment(segment.memberName)
                            is NormalizedJsonPathSegment.IndexSegment ->
                                DCQLClaimsPathPointerSegment.IndexSegment(segment.index)
                        }
                    }
                if (segments.isNotEmpty()) {
                    DCQLClaimsPathPointer(segments.toNonEmptyList())
                } else {
                    null
                }
            }
            ?.toSet()
            ?: emptySet()
        return claimPaths
    }

    /**
     * Aggregates all unique [DCQLClaimsPathPointer]s from a list of policies.
     */
    private fun unionClaimSets(
        applicablePolicies: List<DisclosurePolicy>,
        querySelector: (DisclosurePolicy) -> DCQLQuery?
    ): Set<DCQLClaimsPathPointer> {
        val claimSets = applicablePolicies
            .mapNotNull(querySelector)
            .flatMap { query ->
                query.credentials
                    .filterIsInstance<DCQLSdJwtCredentialQuery>()
                    .flatMap { it.claims?.filterIsInstance<DCQLJsonClaimsQuery>()?.map { it.path } ?: emptyList() }
            }
            .toSet()
        return claimSets
    }

    /**
     * Checks if every claim in [requestedResult] is present in the effective claim set,
     * which is computed as [allowedClaims] minus [deniedClaims].
     */
    private fun allRequestedClaimsPermitted(
        requestedResult: DCQLCredentialQueryMatchingResult?,
        allowedClaims: Set<DCQLClaimsPathPointer>?,
        deniedClaims: Set<DCQLClaimsPathPointer>
    ): Boolean {
        if (requestedResult == null) return false
        val requestedClaims = extractClaimPaths(requestedResult)

        val effectiveClaims = allowedClaims?.minus(deniedClaims)
        return effectiveClaims?.containsAll(requestedClaims) ?: false
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

    /**
     * Determines if a verifier's request is permitted by a given set of [applicablePolicies].
     */
    fun validateRequestedClaims(
        applicablePolicies: List<DisclosurePolicy>,
        requestedResult: DCQLCredentialQueryMatchingResult?
    ): Boolean {
        val allowedClaims = unionClaimSets(applicablePolicies) { it.allowQuery }
        val deniedClaims = unionClaimSets(applicablePolicies) { it.denyQuery }

        return allRequestedClaimsPermitted(requestedResult, allowedClaims, deniedClaims)
    }
}
