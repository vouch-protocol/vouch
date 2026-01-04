"""
Tests for Chain of Custody (Delegation Chain) functionality.

Tests the ability for agents to prove they are acting on behalf of
a user or another agent through recursive delegation chains.
"""

import pytest
from vouch import Signer, Verifier, generate_identity, DelegationLink


class TestDelegationChain:
    """Test delegation chain functionality."""

    @pytest.fixture
    def user_identity(self):
        """Create a user identity."""
        return generate_identity(domain="user.example.com")

    @pytest.fixture
    def agent_a_identity(self):
        """Create Agent A identity."""
        return generate_identity(domain="agent-a.ai")

    @pytest.fixture
    def agent_b_identity(self):
        """Create Agent B identity."""
        return generate_identity(domain="agent-b.ai")

    @pytest.fixture
    def agent_c_identity(self):
        """Create Agent C identity."""
        return generate_identity(domain="agent-c.ai")

    def test_single_hop_no_delegation(self, user_identity):
        """Test that tokens without delegation have empty chain."""
        signer = Signer(private_key=user_identity.private_key_jwk, did=user_identity.did)

        token = signer.sign({"action": "read_file"})

        is_valid, passport = Verifier.verify(token, public_key_jwk=user_identity.public_key_jwk)

        assert is_valid
        assert passport.delegation_chain == []
        assert passport.iss == user_identity.did

    def test_two_hop_delegation(self, user_identity, agent_a_identity):
        """Test User -> Agent A delegation chain."""
        # User creates initial token authorizing Agent A
        user_signer = Signer(private_key=user_identity.private_key_jwk, did=user_identity.did)
        user_token = user_signer.sign({"action": "analyze_data"})

        # Agent A creates token with parent delegation
        agent_a_signer = Signer(
            private_key=agent_a_identity.private_key_jwk, did=agent_a_identity.did
        )
        agent_a_token = agent_a_signer.sign({"action": "query_database"}, parent_token=user_token)

        # Verify Agent A's token
        is_valid, passport = Verifier.verify(
            agent_a_token, public_key_jwk=agent_a_identity.public_key_jwk
        )

        assert is_valid
        assert len(passport.delegation_chain) == 1
        assert passport.delegation_chain[0].iss == user_identity.did
        assert passport.delegation_chain[0].sub == agent_a_identity.did

    def test_three_hop_delegation(self, user_identity, agent_a_identity, agent_b_identity):
        """Test User -> Agent A -> Agent B (3-hop chain)."""
        # Step 1: User authorizes Agent A
        user_signer = Signer(private_key=user_identity.private_key_jwk, did=user_identity.did)
        user_token = user_signer.sign({"action": "analyze_data"})

        # Step 2: Agent A delegates to Agent B
        agent_a_signer = Signer(
            private_key=agent_a_identity.private_key_jwk, did=agent_a_identity.did
        )
        agent_a_token = agent_a_signer.sign({"action": "fetch_records"}, parent_token=user_token)

        # Step 3: Agent B acts with delegated authority
        agent_b_signer = Signer(
            private_key=agent_b_identity.private_key_jwk, did=agent_b_identity.did
        )
        agent_b_token = agent_b_signer.sign({"action": "query_api"}, parent_token=agent_a_token)

        # Verify Agent B's token
        is_valid, passport = Verifier.verify(
            agent_b_token, public_key_jwk=agent_b_identity.public_key_jwk
        )

        assert is_valid
        assert len(passport.delegation_chain) == 2

        # First link: User -> Agent A
        assert passport.delegation_chain[0].iss == user_identity.did
        assert passport.delegation_chain[0].sub == agent_a_identity.did

        # Second link: Agent A -> Agent B
        assert passport.delegation_chain[1].iss == agent_a_identity.did
        assert passport.delegation_chain[1].sub == agent_b_identity.did

    def test_max_depth_enforcement(
        self, user_identity, agent_a_identity, agent_b_identity, agent_c_identity
    ):
        """Test that max chain depth (5) is enforced."""
        # Build a chain of 6 agents (which creates 5 delegation links - the max)
        identities = [generate_identity(domain=f"agent-{i}.ai") for i in range(7)]

        # Start with first agent (no parent - no chain yet)
        current_token = Signer(
            private_key=identities[0].private_key_jwk, did=identities[0].did
        ).sign({"action": "step_0"})

        # Build 5 more delegations (creates 5 links - the max allowed)
        for i in range(1, 6):
            current_token = Signer(
                private_key=identities[i].private_key_jwk, did=identities[i].did
            ).sign({"action": f"step_{i}"}, parent_token=current_token)

        # This should work (5 links)
        is_valid, passport = Verifier.verify(
            current_token, public_key_jwk=identities[5].public_key_jwk
        )
        assert is_valid
        assert len(passport.delegation_chain) == 5  # Exactly at max

        # Trying to add 6th link should fail
        with pytest.raises(ValueError, match="max depth"):
            Signer(private_key=identities[6].private_key_jwk, did=identities[6].did).sign(
                {"action": "step_6"}, parent_token=current_token
            )

    def test_delegation_chain_with_reputation(self, user_identity, agent_a_identity):
        """Test delegation chain combined with reputation score."""
        user_signer = Signer(private_key=user_identity.private_key_jwk, did=user_identity.did)
        user_token = user_signer.sign({"action": "authorize"}, reputation_score=90)

        agent_a_signer = Signer(
            private_key=agent_a_identity.private_key_jwk, did=agent_a_identity.did
        )
        agent_a_token = agent_a_signer.sign(
            {"action": "execute"}, parent_token=user_token, reputation_score=75
        )

        is_valid, passport = Verifier.verify(
            agent_a_token, public_key_jwk=agent_a_identity.public_key_jwk
        )

        assert is_valid
        assert len(passport.delegation_chain) == 1
        assert passport.reputation_score == 75

    def test_delegation_link_has_intent(self, user_identity, agent_a_identity):
        """Test that delegation links capture the intent."""
        user_signer = Signer(private_key=user_identity.private_key_jwk, did=user_identity.did)
        user_token = user_signer.sign({"action": "manage_files"})

        agent_a_signer = Signer(
            private_key=agent_a_identity.private_key_jwk, did=agent_a_identity.did
        )
        intent = {"action": "read_file", "path": "/data/report.pdf"}
        agent_a_token = agent_a_signer.sign(intent, parent_token=user_token)

        is_valid, passport = Verifier.verify(
            agent_a_token, public_key_jwk=agent_a_identity.public_key_jwk
        )

        assert is_valid
        assert len(passport.delegation_chain) == 1

        # The intent should be captured in the link
        link = passport.delegation_chain[0]
        assert "read_file" in link.intent
        assert "/data/report.pdf" in link.intent


class TestDelegationLinkDataclass:
    """Test DelegationLink dataclass."""

    def test_delegation_link_creation(self):
        """Test creating a DelegationLink."""
        link = DelegationLink(
            iss="did:web:alice.com",
            sub="did:web:agent.ai",
            intent='{"action": "read"}',
            iat=1704268800,
            signature="abc123",
        )

        assert link.iss == "did:web:alice.com"
        assert link.sub == "did:web:agent.ai"
        assert link.intent == '{"action": "read"}'
        assert link.iat == 1704268800
        assert link.signature == "abc123"
