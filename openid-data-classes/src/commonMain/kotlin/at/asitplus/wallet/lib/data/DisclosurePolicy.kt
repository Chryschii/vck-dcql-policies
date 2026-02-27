package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents an embedded disclosure policy for a credential.
 *
 * @property relyingPartyMetadata Metadata identifying the relying party this policy applies to
 * @property policy A DCQL query specifying which claims may be disclosed
 */
@Serializable
data class DisclosurePolicy(
    @SerialName("relying_party_metadata")
    val relyingPartyMetadata: RelyingPartyMetadata,
    @SerialName("policy")
    val policy: DCQLQuery,
)
