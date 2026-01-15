package at.asitplus.wallet.lib.openid

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import at.asitplus.wallet.lib.data.DisclosurePolicy
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import io.kotest.matchers.nulls.shouldBeNull



val OpenId4VpSdJwtProtocolTest by testSuite {

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    testConfig = TestConfig.aroundEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, AtomicAttribute2023, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )
        it()
    }

    "Selective Disclosure with custom credential" {
        val requestedClaim = AtomicAttribute2023.CLAIM_GIVEN_NAME
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(requestedClaim))
                )
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        authnRequest shouldContain requestedClaim

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        result.verifiableCredentialSdJwt.shouldNotBeNull()
        result.reconstructed[requestedClaim].shouldNotBeNull()
    }

    "Selective Disclosure with EU PID credential with mapped claim names" {
        val requestedClaims = setOf(
            EuPidScheme.SdJwtAttributes.FAMILY_NAME,
            EuPidScheme.SdJwtAttributes.GIVEN_NAME,
            EuPidScheme.SdJwtAttributes.FAMILY_NAME_BIRTH, // "birth_family_name" instead of "family_name_birth"
            EuPidScheme.SdJwtAttributes.GIVEN_NAME_BIRTH, // "birth_given_name" instead of "given_name_birth"
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(EuPidScheme, SD_JWT, requestedClaims)
                )
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        result.verifiableCredentialSdJwt.shouldNotBeNull()
        requestedClaims.forEach {
            it.shouldBeIn(result.reconstructed.keys)
            result.reconstructed[it].shouldNotBeNull()
        }
    }

    "Embedded Disclosure Policy restricts claims" {
        holderAgent = HolderAgent(holderKeyMaterial)

        // Policy which allows only given_name for this verifier
        val policy = DisclosurePolicy(
            relyingPartyId = clientId,
            policy = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                            )
                        )
                    )
                )
            )
        )

        // Issue credential
        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

        // Add the disclosure policy to the credential
        val credentialWithPolicy = when (credentialToBeIssued) {
            is CredentialToBeIssued.VcSd -> credentialToBeIssued.copy(
                disclosurePolicies = listOf(policy)
            )
            else -> error("Expected VcSd credential")
        }

        val credential = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(credentialWithPolicy).getOrThrow()

        holderAgent.storeCredential(credential.toStoreCredentialInput())

        // Verifier requests BOTH claims
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(
                            AtomicAttribute2023.CLAIM_GIVEN_NAME,
                            AtomicAttribute2023.CLAIM_FAMILY_NAME
                        )
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.RestrictedSdJwt>()

        // Verify that only given_name disclosed & family_name blocked by policy
        result.reconstructed[AtomicAttribute2023.CLAIM_GIVEN_NAME].shouldNotBeNull()
        result.reconstructed[AtomicAttribute2023.CLAIM_FAMILY_NAME].shouldBeNull()
    }

}
