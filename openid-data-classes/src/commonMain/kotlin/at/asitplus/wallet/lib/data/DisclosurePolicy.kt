package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents an embedded disclosure policy for a credential.
 *
 * @property relyingPartyAttributes Attributes identifying which relying party this policy applies to.
 * @property policy A DCQL query specifying which credentials and claims may be disclosed.
 */
@Serializable
data class DisclosurePolicy(
    @SerialName("relyingPartyAttributes")
    val relyingPartyAttributes: RelyingPartyAttributes,
    @SerialName("policy")
    val policy: DCQLQuery,
)
