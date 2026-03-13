package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
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
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.validation.sdJwt.DisclosurePolicyValidator
import at.asitplus.wallet.lib.data.RelyingPartyContext
import io.kotest.matchers.shouldBe

private object RelyingPartyQueryBuilder {
    fun forClientId(clientId: String): DCQLQuery {
        return DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier("rp_filter"),
                    format = CredentialFormatEnum.DC_SD_JWT,
                    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                        vctValues = listOf(RelyingPartyContext.TYPE)
                    ),
                    claims = DCQLClaimsQueryList(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer("client_id"),
                            values = listOf(DCQLExpectedClaimValue.StringValue(clientId))
                        )
                    )
                )
            )
        )
    }
}

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
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy which allows only given_name for this verifier
        val policy = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
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

        // Verifier requests BOTH claims - policy only allows given_name, so this must fail
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
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "Policy selection matches correct policy by client_id" {
        // Creates two policies for different verifiers and checks if only one gets selected
        val policy1 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId("https://verifier1.example.com"),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy1"),
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

        val policy2 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId("https://verifier2.example.com"),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy2"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            )
                        )
                    )
                )
            )
        )

        val policies = listOf(policy1, policy2)
        val context = RelyingPartyContext.fromRequest(
            AuthenticationRequestParameters(clientId = "https://verifier1.example.com")
        )
        val matched = DisclosurePolicyValidator.findApplicablePolicies(policies, context)

        matched.size shouldBe 1
        matched.first() shouldBe policy1
    }

    "Multiple policies allow requested claims" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy 1: allows given_name
        val policy1 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy1"),
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

        // Policy 2: also allows given_name
        val policy2 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy2"),
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

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

        val credentialWithPolicies = when (credentialToBeIssued) {
            is CredentialToBeIssued.VcSd -> credentialToBeIssued.copy(
                disclosurePolicies = listOf(policy1, policy2)
            )
            else -> error("Expected VcSd credential")
        }

        val credential = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(credentialWithPolicies).getOrThrow()

        holderAgent.storeCredential(credential.toStoreCredentialInput())

        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        val sdJwtResult = result.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_GIVEN_NAME].shouldNotBeNull()
    }

    "Multiple policies with non-overlapping allow sets permit union of claims" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy 1: allows only given_name
        val policy1 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy1"),
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

        // Policy 2: allows only family_name
        val policy2 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy2"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            )
                        )
                    )
                )
            )
        )

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

        val credentialWithPolicies = when (credentialToBeIssued) {
            is CredentialToBeIssued.VcSd -> credentialToBeIssued.copy(
                disclosurePolicies = listOf(policy1, policy2)
            )
            else -> error("Expected VcSd credential")
        }

        val credential = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(credentialWithPolicies).getOrThrow()

        holderAgent.storeCredential(credential.toStoreCredentialInput())

        // Request both claims - allowed separately, so union permits it
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(
                            AtomicAttribute2023.CLAIM_GIVEN_NAME,
                            AtomicAttribute2023.CLAIM_FAMILY_NAME)
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        val sdJwtResult = result.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_GIVEN_NAME].shouldNotBeNull()
        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_FAMILY_NAME].shouldNotBeNull()
    }

    "Deny policy blocks claim even when allow policy permits it" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Allow given_name and family_name, but explicitly deny family_name
        val policy = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("allow"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            )
                        )
                    )
                )
            ),
            denyQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("deny"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            )
                        )
                    )
                )
            )
        )

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

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

        // Request family_name - allowed by allowQuery but denied by denyQuery
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "No matching policy denies all claims" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy for a different verifier
        val policy = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId("https://different-verifier.example.com"),
            allowQuery = DCQLQuery(
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

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

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

        // No matching policy means fully restricted - no requested claims allowed
        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "Three policies with different allow sets - union permits superset" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy 1: allows given_name, family_name, date_of_birth
        val policy1 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy1"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_DATE_OF_BIRTH)
                            )
                        )
                    )
                )
            )
        )

        // Policy 2: allows given_name, date_of_birth
        val policy2 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy2"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                            ),
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_DATE_OF_BIRTH)
                            )
                        )
                    )
                )
            )
        )

        // Policy 3: allows only date_of_birth
        val policy3 = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("policy3"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_DATE_OF_BIRTH)
                            )
                        )
                    )
                )
            )
        )

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

        val credentialWithPolicies = when (credentialToBeIssued) {
            is CredentialToBeIssued.VcSd -> credentialToBeIssued.copy(
                disclosurePolicies = listOf(policy1, policy2, policy3)
            )
            else -> error("Expected VcSd credential")
        }

        val credential = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(credentialWithPolicies).getOrThrow()

        holderAgent.storeCredential(credential.toStoreCredentialInput())

        // Union of all three allowPolicies = {given_name, family_name, date_of_birth}
        val authnRequest1 = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse1 = holderOid4vp.createAuthnResponse(authnRequest1).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result1 = verifierOid4vp.validateAuthnResponse(authnResponse1.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        result1.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            .reconstructed[AtomicAttribute2023.CLAIM_GIVEN_NAME].shouldNotBeNull()

        // Request date_of_birth - present in all three policies
        val authnRequest2 = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(AtomicAttribute2023.CLAIM_DATE_OF_BIRTH)
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse2 = holderOid4vp.createAuthnResponse(authnRequest2).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result2 = verifierOid4vp.validateAuthnResponse(authnResponse2.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        result2.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            .reconstructed[AtomicAttribute2023.CLAIM_DATE_OF_BIRTH].shouldNotBeNull()
    }

    "No matching relying party context - no policy enforcement but also no claims" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy scoped to a completely different verifier — will never match the actual clientId
        val policy = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId("https://unrelated-verifier.example.com"),
            allowQuery = DCQLQuery(
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

        val credentialToBeIssued = DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            AtomicAttribute2023,
            SD_JWT
        ).getOrThrow()

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

        // Request both claims — no policy matches this verifier, so every claim is blocked
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
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "Sector-wide policy and client-specific policy both apply" {
        val sectorPolicy = DisclosurePolicy(
            relyingPartyQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("rp_filter_sector"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(RelyingPartyContext.TYPE)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer("sector"),
                                values = listOf(DCQLExpectedClaimValue.StringValue("health"))
                            )
                        )
                    )
                )
            ),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("sector_allow"),
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

        val clientPolicy = DisclosurePolicy(
            relyingPartyQuery = RelyingPartyQueryBuilder.forClientId("https://health-app.example.com"),
            allowQuery = DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLSdJwtCredentialQuery(
                        id = DCQLCredentialQueryIdentifier("client_allow"),
                        format = CredentialFormatEnum.DC_SD_JWT,
                        meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                            vctValues = listOf(AtomicAttribute2023.sdJwtType)
                        ),
                        claims = DCQLClaimsQueryList(
                            DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME)
                            )
                        )
                    )
                )
            )
        )

        val relyingPartyContext = RelyingPartyContext.fromMap(
            mapOf(
                "client_id" to "https://health-app.example.com",
                "sector" to "health",
            )
        )
        val matched = DisclosurePolicyValidator.findApplicablePolicies(
            policies = listOf(sectorPolicy, clientPolicy),
            relyingPartyContext = relyingPartyContext,
        )

        // Both policies must match: one on sector, one on client_id
        matched.size shouldBe 2
        matched shouldBe listOf(sectorPolicy, clientPolicy)
    }
}