package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.data.DisclosurePolicy

/**
 * Validates disclosure policies by matching relying party information against policy filters.
 */
object DisclosurePolicyValidator {

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

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Creates a filter for matching policies by client ID.
     *
     * @param clientId The client ID to match
     * @param clientIdKey The metadata field key for client ID (default: "client_id")
     * @return A filter that matches policies with the specified client ID
     */
    fun createClientIdFilter(
        clientId: String,
        clientIdKey: String = "client_id"
    ): DisclosurePolicyFilter {
        return AttributeValueFilter(clientIdKey, clientId)
    }
}
