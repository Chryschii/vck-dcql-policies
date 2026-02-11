package at.asitplus.wallet.lib.agent.validation.sdJwt

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
 * Filter that matches policies based on a specific relying party attribute value.
 *
 * @property attributeKey The attribute key to check (e.g., "client_id", "domain")
 * @property expectedValue The expected value for the attribute
 */
class AttributeValueFilter(
    private val attributeKey: String,
    private val expectedValue: String
) : DisclosurePolicyFilter {

    override fun matches(policy: DisclosurePolicy): Boolean {
        return policy.relyingPartyAttributes[attributeKey] == expectedValue
    }
}

/**
 * Filter that matches policies using a custom predicate function.
 *
 * @property attributeKey The attribute key to evaluate
 * @property predicate Custom function to determine if the attribute value matches
 */
class AttributePredicateFilter(
    private val attributeKey: String,
    private val predicate: (String?) -> Boolean
) : DisclosurePolicyFilter {

    override fun matches(policy: DisclosurePolicy): Boolean {
        val value = policy.relyingPartyAttributes[attributeKey]
        return predicate(value)
    }
}

/**
 * Filter that matches policies where the relying party attributes contain a specific key.
 *
 * @property attributeKey The attribute key to check for existence
 */
class AttributeExistsFilter(
    private val attributeKey: String
) : DisclosurePolicyFilter {

    override fun matches(policy: DisclosurePolicy): Boolean {
        return policy.relyingPartyAttributes.contains(attributeKey)
    }
}

/**
 * Filter that matches policies where an attribute value is in a set of allowed values.
 *
 * @property attributeKey The attribute key to check
 * @property allowedValues Set of allowed values
 */
class AttributeInSetFilter(
    private val attributeKey: String,
    private val allowedValues: Set<String>
) : DisclosurePolicyFilter {

    override fun matches(policy: DisclosurePolicy): Boolean {
        val value = policy.relyingPartyAttributes[attributeKey] ?: return false
        return value in allowedValues
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
