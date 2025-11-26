package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL

import kotlin.time.Instant
import kotlinx.serialization.Polymorphic
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration

/**
 * The core of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/): a credential.
 */
@Serializable
data class VerifiableCredential(
    @SerialName("id")
    val id: String,
    @SerialName("type")
    val type: Collection<String>,
    @SerialName("issuer")
    val issuer: String,
    @Serializable(with = InstantStringSerializer::class)
    @SerialName("issuanceDate")
    val issuanceDate: Instant,
    @Serializable(with = NullableInstantStringSerializer::class)
    @SerialName("expirationDate")
    val expirationDate: Instant?,
    @SerialName("status")
    val credentialStatus: Status? = null,
    @Polymorphic
    @SerialName("credentialSubject")
    val credentialSubject: CredentialSubject,
    @SerialName("disclosurePolicies")
    val disclosurePolicies: List<DisclosurePolicy>? = null,
) {
    constructor(
        id: String,
        issuer: String,
        lifetime: Duration,
        credentialStatus: Status,
        credentialSubject: CredentialSubject,
        credentialType: String,
        issuanceDate: Instant = Clock.System.now(),
        expirationDate: Instant? = Clock.System.now() + lifetime,
        disclosurePolicies: List<DisclosurePolicy>? = null,
    ) : this(
        id = id,
        type = listOf(VERIFIABLE_CREDENTIAL, credentialType),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        credentialStatus = credentialStatus,
        credentialSubject = credentialSubject,
        disclosurePolicies = disclosurePolicies,
    )

    constructor(
        id: String,
        issuer: String,
        issuanceDate: Instant,
        expirationDate: Instant?,
        credentialStatus: Status,
        credentialSubject: CredentialSubject,
        credentialType: String,
        disclosurePolicies: List<DisclosurePolicy>? = null,
    ) : this(
        id = id,
        type = listOf(VERIFIABLE_CREDENTIAL, credentialType),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        credentialStatus = credentialStatus,
        credentialSubject = credentialSubject,
        disclosurePolicies = disclosurePolicies,
    )
}