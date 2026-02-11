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
import at.asitplus.wallet.lib.agent.validation.sdJwt.AttributeInSetFilter
import at.asitplus.wallet.lib.agent.validation.sdJwt.AttributePredicateFilter
import at.asitplus.wallet.lib.agent.validation.sdJwt.AttributeValueFilter
import at.asitplus.wallet.lib.agent.validation.sdJwt.CompositeDisclosurePolicyFilter
import at.asitplus.wallet.lib.agent.validation.sdJwt.DisclosurePolicyValidator
import at.asitplus.wallet.lib.data.RelyingPartyAttributes
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe


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
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
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
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "Filter-based policy selection matches correct policy" {
        // Create two policies for different verifiers
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId("https://verifier1.example.com"),
            policy = DCQLQuery(
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
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId("https://verifier2.example.com"),
            policy = DCQLQuery(
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

        // Use filter to find policy for verifier1
        val filter = AttributeValueFilter("client_id", "https://verifier1.example.com")
        val matchedPolicy = DisclosurePolicyValidator.findMatchingPolicy(policies, filter)

        matchedPolicy.shouldNotBeNull()
        matchedPolicy.relyingPartyAttributes["client_id"] shouldBe "https://verifier1.example.com"
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

        // Policy 1: Allows given_name
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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

        // Policy 2: Also allows given_name (redundant but valid)
        val policy2 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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

    "Multiple policies with conflicting restrictions block disclosure" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy 1: Allows only given_name
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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

        // Policy 2: Allows only family_name (conflicts with policy1)
        val policy2 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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
        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
    }

    "No matching policy allows all claims" {
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
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId("https://different-verifier.example.com"),
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

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        // No matching policy means no restrictions - all requested claims allowed
        val sdJwtResult = result.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_GIVEN_NAME].shouldNotBeNull()
        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_FAMILY_NAME].shouldNotBeNull()
    }

    "Composite filter with multiple attributes" {
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromMap(
                mapOf(
                    "client_id" to "https://verifier1.example.com",
                    "purpose" to "authentication"
                )
            ),
            policy = DCQLQuery(
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
            relyingPartyAttributes = RelyingPartyAttributes.fromMap(
                mapOf(
                    "client_id" to "https://verifier1.example.com",
                    "purpose" to "payment"
                )
            ),
            policy = DCQLQuery(
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

        // Filter for client_id AND purpose
        val compositeFilter = CompositeDisclosurePolicyFilter(
            filters = listOf(
                AttributeValueFilter("client_id", "https://verifier1.example.com"),
                AttributeValueFilter("purpose", "authentication")
            ),
            operator = CompositeDisclosurePolicyFilter.LogicalOperator.AND
        )

        val matchedPolicy = DisclosurePolicyValidator.findMatchingPolicy(policies, compositeFilter)

        matchedPolicy.shouldNotBeNull()
        matchedPolicy.relyingPartyAttributes["purpose"] shouldBe "authentication"
    }

    "AttributeInSetFilter matches multiple allowed values" {
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId("https://verifier-prod.example.com"),
            policy = DCQLQuery(
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
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId("https://verifier-staging.example.com"),
            policy = DCQLQuery(
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

        // Filter for multiple allowed client IDs
        val inSetFilter = AttributeInSetFilter(
            "client_id",
            setOf(
                "https://verifier-prod.example.com",
                "https://verifier-dev.example.com"
            )
        )

        val matchedPolicies = DisclosurePolicyValidator.findMatchingPolicies(policies, inSetFilter)

        matchedPolicies.size shouldBe 1
        matchedPolicies.first().relyingPartyAttributes["client_id"] shouldBe "https://verifier-prod.example.com"
    }

    "Three policies with different restrictions - most restrictive wins" {
        val holderAgent = HolderAgent(holderKeyMaterial)
        val holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )

        // Policy 1: allows given_name and family_name and date_of_birth
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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

        // Policy 2: allows given_name and date_of_birth
        val policy2 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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
            relyingPartyAttributes = RelyingPartyAttributes.fromClientId(ClientIdScheme.RedirectUri(clientId).clientId),
            policy = DCQLQuery(
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

        // First request: Ask for given_name (allowed by policy1 and policy2, but not policy3)
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
        verifierOid4vp.validateAuthnResponse(authnResponse1.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()

        // Second request: Ask for date_of_birth (only what the most restrictive policy allows)
        val authnRequest2 = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        AtomicAttribute2023,
                        SD_JWT,
                        setOf(
                            AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
                        )
                    )
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse2 = holderOid4vp.createAuthnResponse(authnRequest2).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val result = verifierOid4vp.validateAuthnResponse(authnResponse2.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()

        val sdJwtResult = result.validationResults.values.single()
            .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        sdJwtResult.reconstructed[AtomicAttribute2023.CLAIM_DATE_OF_BIRTH].shouldNotBeNull()
    }

    "AttributePredicateFilter with custom matching logic" {
        val policy1 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromMap(
                mapOf(
                    "client_id" to "https://verifier.example.com",
                    "trust_level" to "high"
                )
            ),
            policy = DCQLQuery(
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
                            )
                        )
                    )
                )
            )
        )

        val policy2 = DisclosurePolicy(
            relyingPartyAttributes = RelyingPartyAttributes.fromMap(
                mapOf(
                    "client_id" to "https://verifier.example.com",
                    "trust_level" to "low"
                )
            ),
            policy = DCQLQuery(
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

        val policies = listOf(policy1, policy2)

        // Use predicate filter to match policies with high trust level
        val predicateFilter = CompositeDisclosurePolicyFilter(
            filters = listOf(
                AttributeValueFilter("client_id", "https://verifier.example.com"),
                AttributePredicateFilter("trust_level") { value ->
                    value == "high" || value == "medium"
                }
            ),
            operator = CompositeDisclosurePolicyFilter.LogicalOperator.AND
        )

        val matchedPolicies = DisclosurePolicyValidator.findMatchingPolicies(policies, predicateFilter)

        matchedPolicies.size shouldBe 1
        matchedPolicies.first().relyingPartyAttributes["trust_level"] shouldBe "high"
    }
}
