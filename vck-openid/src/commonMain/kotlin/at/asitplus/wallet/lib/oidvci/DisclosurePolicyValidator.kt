package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.data.DisclosurePolicy

/**
 * A utility to validate if a verifier's request complies with the embedded disclosure policies
 * of a set of verifiable credentials.
 */
object DisclosurePolicyValidator {

    fun validate(
        relyingPartyId: String,
        requestQuery: DCQLQuery,
        policies: List<DisclosurePolicy>
    ): PolicyValidationResult {
        // Find policies matching this relying party
        val applicablePolicies = policies.filter {
            it.relyingPartyId == relyingPartyId
        }

        if (applicablePolicies.isEmpty()) {
            return PolicyValidationResult.Success
        }

        // Validate each policy
        applicablePolicies.forEach { policy ->
            val validationResult = validateSinglePolicy(policy, requestQuery)
            if (validationResult is PolicyValidationResult.Failure) {
                return validationResult
            }
        }
        return PolicyValidationResult.Success
    }

    /**
     * Validates a single policy against the verifier's request
     */
    private fun validateSinglePolicy(
        policy: DisclosurePolicy,
        requestQuery: DCQLQuery
    ): PolicyValidationResult {
        val policyQuery = policy.policy

        // Get all requested claim paths from the verifier's request
        val requestedPaths = requestQuery.credentials.flatMap { credentialQuery ->
            credentialQuery.claims?.mapNotNull { claimQuery ->
                extractClaimPath(claimQuery)
            } ?: emptyList()
        }.toSet()

        // Get all allowed claim paths from the policy
        val allowedPaths = policyQuery.credentials.flatMap { credentialQuery ->
            credentialQuery.claims?.mapNotNull { claimQuery ->
                extractClaimPath(claimQuery)
            } ?: emptyList()
        }.toSet()

        // Check if any requested path is NOT in the allowed paths
        val violatingPaths = requestedPaths - allowedPaths

        return if (violatingPaths.isNotEmpty()) {
            PolicyValidationResult.Failure(
                "Requested claims violate policy: ${violatingPaths.joinToString(", ")}"
            )
        } else {
            PolicyValidationResult.Success
        }
    }

    /**
     * Extract the claim path as a string for comparison
     */
    private fun extractClaimPath(claimQuery: DCQLClaimsQuery): String? {
        return when (claimQuery) {
            is DCQLJsonClaimsQuery -> claimQuery.path.segments.joinToString("/") { segment ->
                when (segment) {
                    is DCQLClaimsPathPointerSegment.NameSegment -> segment.name
                    is DCQLClaimsPathPointerSegment.IndexSegment -> "[${segment.index}]"
                    is DCQLClaimsPathPointerSegment.NullSegment -> "null"
                }
            }
            is DCQLIsoMdocClaimsQuery -> claimQuery.path?.segments?.joinToString("/") { segment ->
                when (segment) {
                    is DCQLClaimsPathPointerSegment.NameSegment -> segment.name
                    is DCQLClaimsPathPointerSegment.IndexSegment -> "[${segment.index}]"
                    is DCQLClaimsPathPointerSegment.NullSegment -> "null"
                }
            }
            else -> null
        }
    }
}

/**
 * Represents the result of a disclosure policy validation.
 */
sealed class PolicyValidationResult {
    data object Success : PolicyValidationResult()
    data class Failure(val reason: String) : PolicyValidationResult()
}
