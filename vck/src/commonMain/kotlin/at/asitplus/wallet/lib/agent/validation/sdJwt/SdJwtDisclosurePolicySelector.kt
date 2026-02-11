package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.wallet.lib.data.DisclosurePolicy

/**
 * Selector for finding disclosure policies that match specific filter criteria.
 * Provides various methods for selecting policies from a collection.
 *
 * @property policies The collection of policies to select from
 */
class DisclosurePolicySelector(
    private val policies: List<DisclosurePolicy>
) {

    /**
     * Selects all policies matching the given filter.
     *
     * @param filter The filter to apply
     * @return List of matching policies (may be empty)
     */
    fun select(filter: DisclosurePolicyFilter): List<DisclosurePolicy> {
        return policies.filter { filter.matches(it) }
    }

    /**
     * Selects the first policy matching the filter, or null if none match.
     *
     * @param filter The filter to apply
     * @return The first matching policy, or null
     */
    fun selectFirst(filter: DisclosurePolicyFilter): DisclosurePolicy? {
        return policies.firstOrNull { filter.matches(it) }
    }

    /**
     * Selects policies using a custom predicate function.
     *
     * @param predicate Custom function to determine if a policy should be selected
     * @return List of matching policies
     */
    fun selectWhere(predicate: (DisclosurePolicy) -> Boolean): List<DisclosurePolicy> {
        return policies.filter(predicate)
    }

    /**
     * Selects the first policy matching the predicate, or null if none match.
     *
     * @param predicate Custom function to determine if a policy should be selected
     * @return The first matching policy, or null
     */
    fun selectFirstWhere(predicate: (DisclosurePolicy) -> Boolean): DisclosurePolicy? {
        return policies.firstOrNull(predicate)
    }

    /**
     * Checks if any policy matches the given filter.
     *
     * @param filter The filter to apply
     * @return true if at least one policy matches
     */
    fun any(filter: DisclosurePolicyFilter): Boolean {
        return policies.any { filter.matches(it) }
    }

    /**
     * Checks if all policies match the given filter.
     *
     * @param filter The filter to apply
     * @return true if all policies match
     */
    fun all(filter: DisclosurePolicyFilter): Boolean {
        return policies.all { filter.matches(it) }
    }

    /**
     * Counts how many policies match the given filter.
     *
     * @param filter The filter to apply
     * @return Number of matching policies
     */
    fun count(filter: DisclosurePolicyFilter): Int {
        return policies.count { filter.matches(it) }
    }
}
