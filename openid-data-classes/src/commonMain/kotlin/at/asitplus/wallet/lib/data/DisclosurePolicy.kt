package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents an embedded disclosure policy for a VerifiableCredentialSdJwt.
 *
 * When a presentation request arrives, the relying party's attributes are converted into a
 * pseudo-credential. Every [relyingPartyQuery] from every [DisclosurePolicy] embedded in the
 * credential is matched against that pseudo-credential. Policies whose [relyingPartyQuery]
 * matches are considered applicable have their [allowPolicy] / [denyPolicy] rules enforced.
 *
 * @property relyingPartyQuery A DCQL query run against the relying party pseudo-credential to
 *   decide whether this policy applies to the current request. Can be broad (e.g. match an entire
 *   sector) or narrow (e.g. match a single client ID).
 * @property allowPolicy A DCQL query specifying which claims MAY be disclosed. Only claims
 *   matched by this query are permitted.
 * @property denyPolicy An optional DCQL query specifying which claims MUST NOT be disclosed, even
 *   if they would otherwise be permitted by an [allowPolicy]. Takes precedence over [allowPolicy].
 */
@Serializable
data class DisclosurePolicy(
    @SerialName("relying_party_query")
    val relyingPartyQuery: DCQLQuery,
    @SerialName("allow_policy")
    val allowPolicy: DCQLQuery,
    @SerialName("deny_policy")
    val denyPolicy: DCQLQuery? = null,
)
