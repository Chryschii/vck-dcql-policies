package at.asitplus.wallet.lib.data
import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents an embedded disclosure policy for a credential.
 *
 * This policy defines which claims a specific relying party is authorized to request.
 *
 * @property relyingPartyId A unique identifier for the Relying Party (Verifier) this policy applies to.
 * @property policy A DCQL query that specifies the set of credentials and claims that are
 *                  permissible to be disclosed to this relying party.
 */
@Serializable
data class DisclosurePolicy(
    @SerialName("relyingPartyId")
    val relyingPartyId: String,
    @SerialName("policy")
    val policy: DCQLQuery,
)
