"""
Tests for the Pacing Profile (PAD-125 to PAD-135).

Adversarial by default: every mechanism is exercised on its happy path and then
attacked the way the corresponding disclosure says it must resist, so a
regression that quietly admits authority fails here rather than in production.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from vouch import Signer, generate_identity
from vouch.pacing import (
    AdmissionController,
    AuthorshipGraph,
    CheckpointedHashChain,
    LivenessChain,
    NonceLedger,
    PacingError,
    PeriodAccounting,
    QuorumPolicy,
    Threshold,
    accumulate,
    advancement_credential,
    attenuate_envelope,
    attest_restraint,
    authorize_step,
    authorship_credential,
    build_census,
    build_openings,
    chain_census,
    check_admission,
    check_advancement,
    check_load,
    check_ordering,
    check_ratio,
    check_results,
    check_step,
    closure_record,
    collect_round,
    commit_measurement,
    commit_policy,
    compute_mandate,
    concern_object,
    declared_ledger,
    decommission_device,
    endorse_authorization,
    endorse_epoch,
    enroll_device,
    escrow_keypair,
    evaluate_predicate,
    evaluate_release,
    human_review,
    identifier_for,
    is_attenuation,
    issue_execution,
    load_authorization,
    measurement_record,
    object_to_step,
    open_round,
    open_threshold,
    oversight_receipt,
    pace_epoch,
    permitted_classes,
    publish_policy,
    publish_results,
    reconcile,
    register_concern,
    register_step,
    reveal_measurement,
    sample_workloads,
    select_epoch,
    step_credential,
    unseal_concern,
    verify_amendment_chain,
    verify_epoch,
    verify_open,
    verify_release,
    verify_restraint,
    work_record,
    workload_commitment,
)
from vouch.pacing import census as census_mod
from vouch.pacing import custody as custody_mod
from vouch.pacing import disclosure as disclosure_mod
from vouch.pacing import fuse as fuse_mod
from vouch.pacing import load_auth as load_mod
from vouch.pacing import oversight as oversight_mod
from vouch.pacing import pace as pace_mod
from vouch.pacing import prereg as prereg_mod
from vouch.pacing import recursion as recursion_mod
from vouch.pacing import redline as redline_mod
from vouch.pacing import restraint as restraint_mod

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def identity(domain):
    """A fresh keypair and Signer for a test principal."""
    keypair = generate_identity(domain=domain)
    return keypair, Signer(private_key=keypair.private_key_jwk, did=keypair.did)


# ---------------------------------------------------------------------------
# PAD-125: census-complete compute ceiling attestation
# ---------------------------------------------------------------------------


class TestCensusAndRestraint:
    def _fleet(self, count=4):
        operator_kp, operator = identity("operator.example.com")
        devices = [identity("device%d.example.com" % index) for index in range(count)]
        enrollments = [
            enroll_device(
                operator,
                device_did=signer.get_did(),
                device_id="serial-%d" % index,
                hardware_attestation={"quote": "attestation-%d" % index},
            )
            for index, (_, signer) in enumerate(devices)
        ]
        census, reasons = build_census(
            operator.get_did(), enrollments, {operator.get_did(): operator_kp.public_key_jwk}
        )
        assert reasons == []
        return operator_kp, operator, devices, enrollments, census

    def _period(self, census, devices, plan, period="2026-Q3"):
        accounting = PeriodAccounting(census=census, period=period)
        per_record = {}
        for (keypair, signer), (handle, magnitude) in zip(devices, plan):
            record, blinding = work_record(
                signer,
                census_commitment=census.commitment_digest,
                period=period,
                workload=handle,
                magnitude=magnitude,
            )
            assert accounting.add_record(record, keypair.public_key_jwk)
            per_record[signer.get_did()] = (magnitude, blinding)
        return accounting, per_record

    def test_census_root_is_stable_and_counts_devices(self):
        _, operator, _, enrollments, census = self._fleet()
        assert census.cardinality == 4
        rebuilt, reasons = build_census(
            operator.get_did(),
            list(reversed(enrollments)),
            {operator.get_did(): generate_identity(domain="x.example.com").public_key_jwk},
        )
        assert reasons  # wrong key must not verify
        assert rebuilt is None

    def test_duplicate_enrollment_is_refused(self):
        operator_kp, operator, _, enrollments, _ = self._fleet()
        _, reasons = build_census(
            operator.get_did(),
            enrollments + [enrollments[0]],
            {operator.get_did(): operator_kp.public_key_jwk},
        )
        assert census_mod.REASON_DUPLICATE_DEVICE in reasons

    def test_complete_period_verifies(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        alpha = workload_commitment("run-alpha", salt)
        beta = workload_commitment("run-beta", salt)
        accounting, per_record = self._period(
            census, devices, [(alpha, 30), (alpha, 25), (beta, 10), (beta, 5)]
        )
        openings = build_openings(accounting, per_record)
        attestation = attest_restraint(
            operator, accounting, ceiling=60, quota=100, openings=openings
        )
        assert verify_restraint(attestation, operator_kp.public_key_jwk, accounting) == []

    def test_ceiling_and_quota_are_enforced(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        alpha = workload_commitment("run-alpha", salt)
        accounting, per_record = self._period(
            census, devices, [(alpha, 30), (alpha, 25), (alpha, 10), (alpha, 5)]
        )
        openings = build_openings(accounting, per_record)
        over_ceiling = attest_restraint(
            operator, accounting, ceiling=60, quota=1000, openings=openings
        )
        assert restraint_mod.REASON_CEILING_EXCEEDED in verify_restraint(
            over_ceiling, operator_kp.public_key_jwk, accounting
        )
        over_quota = attest_restraint(
            operator, accounting, ceiling=1000, quota=50, openings=openings
        )
        assert restraint_mod.REASON_QUOTA_EXCEEDED in verify_restraint(
            over_quota, operator_kp.public_key_jwk, accounting
        )

    def test_a_silent_device_breaks_the_period(self):
        """Omitting work means omitting a device, and that is detectable."""
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        handle = workload_commitment("run-alpha", salt)
        accounting, per_record = self._period(census, devices[:3], [(handle, 10)] * 3)
        openings = build_openings(accounting, per_record)
        attestation = attest_restraint(
            operator, accounting, ceiling=100, quota=100, openings=openings
        )
        reasons = verify_restraint(attestation, operator_kp.public_key_jwk, accounting)
        assert restraint_mod.REASON_UNEXPLAINED_ABSENCE in reasons

    def test_absence_must_be_a_signed_dated_event(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        handle = workload_commitment("run-alpha", salt)
        accounting, per_record = self._period(census, devices[:3], [(handle, 10)] * 3)
        absent_signer = devices[3][1]
        assert accounting.add_absence(
            decommission_device(
                operator,
                device_did=absent_signer.get_did(),
                period="2026-Q3",
                reason="scheduled-maintenance",
            ),
            operator_kp.public_key_jwk,
        )
        openings = build_openings(accounting, per_record)
        attestation = attest_restraint(
            operator, accounting, ceiling=100, quota=100, openings=openings
        )
        assert verify_restraint(attestation, operator_kp.public_key_jwk, accounting) == []

    def test_record_from_a_device_outside_the_census_is_refused(self):
        _, _, devices, _, census = self._fleet()
        stranger_kp, stranger = identity("stranger.example.com")
        accounting = PeriodAccounting(census=census, period="2026-Q3")
        record, _ = work_record(
            stranger,
            census_commitment=census.commitment_digest,
            period="2026-Q3",
            workload=workload_commitment("x", secrets.token_bytes(16)),
            magnitude=1,
        )
        assert accounting.add_record(record, stranger_kp.public_key_jwk) is False
        assert restraint_mod.REASON_NOT_IN_CENSUS in accounting.reasons

    def test_record_bound_to_a_different_census_is_refused(self):
        _, _, devices, _, census = self._fleet()
        accounting = PeriodAccounting(census=census, period="2026-Q3")
        keypair, signer = devices[0]
        record, _ = work_record(
            signer,
            census_commitment="uSOMEOTHERCENSUS",
            period="2026-Q3",
            workload=workload_commitment("x", secrets.token_bytes(16)),
            magnitude=1,
        )
        assert accounting.add_record(record, keypair.public_key_jwk) is False
        assert restraint_mod.REASON_WRONG_CENSUS in accounting.reasons

    def test_a_lying_opening_does_not_verify(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        handle = workload_commitment("run-alpha", salt)
        accounting, per_record = self._period(census, devices, [(handle, 40)] * 4)
        openings = build_openings(accounting, per_record)
        magnitude, blinding = openings[handle]
        openings[handle] = (magnitude - 100, blinding)
        attestation = attest_restraint(
            operator, accounting, ceiling=1000, quota=1000, openings=openings
        )
        assert restraint_mod.REASON_BAD_OPENING in verify_restraint(
            attestation, operator_kp.public_key_jwk, accounting
        )

    def test_sampling_is_determined_by_the_log_root(self):
        handles = ["u%02d" % index for index in range(20)]
        first = sample_workloads("uROOT-A", handles, 5)
        assert first == sample_workloads("uROOT-A", handles, 5)
        assert first != sample_workloads("uROOT-B", handles, 5)
        assert len(first) == 5

    def test_operator_cannot_choose_which_workloads_are_opened(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        plan = [(workload_commitment("run-%d" % index, salt), 10) for index in range(4)]
        accounting, per_record = self._period(census, devices, plan)
        openings = build_openings(accounting, per_record)
        attestation = attest_restraint(
            operator,
            accounting,
            ceiling=50,
            quota=1000,
            mode=restraint_mod.MODE_SAMPLED,
            openings=openings,
            seed_root="uLOGROOT",
            sample_size=2,
        )
        assert verify_restraint(attestation, operator_kp.public_key_jwk, accounting) == []
        forged = dict(attestation)
        subject = dict(forged["credentialSubject"])
        subject["seedRoot"] = "uDIFFERENT"
        forged["credentialSubject"] = subject
        assert restraint_mod.REASON_INVALID_PROOF in verify_restraint(
            forged, operator_kp.public_key_jwk, accounting
        )

    def test_external_proof_backend_is_consulted(self):
        operator_kp, operator, devices, _, census = self._fleet()
        salt = secrets.token_bytes(16)
        handle = workload_commitment("run-alpha", salt)
        accounting, _ = self._period(census, devices, [(handle, 10)] * 4)
        restraint_mod.clear_proof_backends()
        attestation = attest_restraint(
            operator,
            accounting,
            ceiling=50,
            quota=100,
            mode=restraint_mod.MODE_EXTERNAL_PROOF,
            external_proof={"backend": "test-range-proof", "opaque": "proof-bytes"},
        )
        assert restraint_mod.REASON_NO_PROOF_BACKEND in verify_restraint(
            attestation, operator_kp.public_key_jwk, accounting
        )
        restraint_mod.register_proof_backend("test-range-proof", lambda proof, params: True)
        try:
            assert verify_restraint(attestation, operator_kp.public_key_jwk, accounting) == []
            restraint_mod.register_proof_backend("test-range-proof", lambda p, q: False)
            assert restraint_mod.REASON_PROOF_REJECTED in verify_restraint(
                attestation, operator_kp.public_key_jwk, accounting
            )
        finally:
            restraint_mod.clear_proof_backends()

    def test_census_is_chained_not_restated(self):
        operator_kp, operator, devices, enrollments, census = self._fleet()
        keys = {operator.get_did(): operator_kp.public_key_jwk}
        retirement = decommission_device(
            operator, device_did=devices[0][1].get_did(), period="2026-Q4", reason="retired"
        )
        next_census, reasons = chain_census(
            census,
            enrollments=[],
            decommissions=[retirement],
            prior_enrollments=enrollments,
            public_keys=keys,
        )
        assert reasons == []
        assert next_census.cardinality == 3
        _, again = chain_census(
            census,
            enrollments=[],
            decommissions=[retirement, retirement],
            prior_enrollments=enrollments,
            public_keys=keys,
        )
        assert census_mod.REASON_UNKNOWN_DEVICE in again

    def test_continuity_chain_detects_a_parked_device(self):
        from vouch.canary import compute_commitment

        _, _, devices, _, census = self._fleet()
        secret = secrets.token_bytes(32)
        prior = {devices[0][1].get_did(): compute_commitment(secret)}
        accounting = PeriodAccounting(census=census, period="2026-Q3")
        keypair, signer = devices[0]
        record, _ = work_record(
            signer,
            census_commitment=census.commitment_digest,
            period="2026-Q3",
            workload=workload_commitment("x", secrets.token_bytes(16)),
            magnitude=1,
            chain_reveal="u" + secrets.token_urlsafe(24),
        )
        accounting.add_record(record, keypair.public_key_jwk)
        assert accounting.check_continuity(prior) == [signer.get_did()]


# ---------------------------------------------------------------------------
# PAD-126: recursion ceiling
# ---------------------------------------------------------------------------


class TestRecursionCeiling:
    def _chain(self, depth):
        human_kp, human = identity("reviewer.example.com")
        agent_kp, agent = identity("agent.example.com")
        graph = AuthorshipGraph()
        graph.add_authorship(
            authorship_credential(
                human,
                artifact_digest="uSEED",
                author_class=recursion_mod.CLASS_HUMAN,
                custody_class=recursion_mod.CUSTODY_HUMAN_PRESENCE,
            ),
            human_kp.public_key_jwk,
        )
        previous = "uSEED"
        for index in range(1, depth + 1):
            current = "uGEN%d" % index
            graph.add_authorship(
                authorship_credential(
                    agent,
                    artifact_digest=current,
                    author_class=recursion_mod.CLASS_AUTONOMOUS,
                    derived_from=[previous],
                ),
                agent_kp.public_key_jwk,
            )
            previous = current
        return graph, human_kp, human, agent_kp, agent

    def test_distance_accumulates_through_derivation(self):
        graph, _, _, _, _ = self._chain(3)
        assert graph.human_distance("uSEED") == 1
        assert graph.human_distance("uGEN1") == 2
        assert graph.human_distance("uGEN3") == 4

    def test_bound_refuses_a_step_past_the_ceiling(self):
        graph, _, _, _, _ = self._chain(3)
        operator_kp, operator = identity("operator.example.com")
        step = step_credential(operator, step_id="run-1", inputs=["uGEN3"], graph=graph, bound=4)
        assert check_step(step, operator_kp.public_key_jwk, graph) == []
        assert recursion_mod.REASON_BOUND_EXCEEDED in check_step(
            step, operator_kp.public_key_jwk, graph, bound=2
        )

    def test_human_review_over_the_exact_digest_resets_the_distance(self):
        graph, human_kp, human, _, _ = self._chain(3)
        graph.add_review(human_review(human, artifact_digest="uGEN3"), human_kp.public_key_jwk)
        assert graph.human_distance("uGEN3") == 1

    def test_a_review_does_not_transfer_to_other_content(self):
        graph, human_kp, human, _, _ = self._chain(3)
        graph.add_review(human_review(human, artifact_digest="uGEN1"), human_kp.public_key_jwk)
        assert graph.human_distance("uGEN1") == 1
        assert graph.human_distance("uGEN3") == 3

    def test_repackaging_does_not_reset_autonomy_depth(self):
        graph, _, _, agent_kp, agent = self._chain(3)
        graph.add_authorship(
            authorship_credential(
                agent,
                artifact_digest="uREPACKAGED",
                author_class=recursion_mod.CLASS_AUTONOMOUS,
                derived_from=["uGEN3"],
            ),
            agent_kp.public_key_jwk,
        )
        assert graph.human_distance("uREPACKAGED") == 5

    def test_artifact_with_no_human_path_is_refused(self):
        agent_kp, agent = identity("agent.example.com")
        operator_kp, operator = identity("operator.example.com")
        graph = AuthorshipGraph()
        graph.add_authorship(
            authorship_credential(
                agent, artifact_digest="uORPHAN", author_class=recursion_mod.CLASS_AUTONOMOUS
            ),
            agent_kp.public_key_jwk,
        )
        step = step_credential(operator, step_id="run-2", inputs=["uORPHAN"], graph=graph, bound=10)
        assert recursion_mod.REASON_NO_HUMAN_PATH in check_step(
            step, operator_kp.public_key_jwk, graph
        )

    def test_a_cycle_does_not_hang_or_grant_a_short_path(self):
        agent_kp, agent = identity("agent.example.com")
        graph = AuthorshipGraph()
        graph.add_authorship(
            authorship_credential(
                agent,
                artifact_digest="uA",
                author_class=recursion_mod.CLASS_AUTONOMOUS,
                derived_from=["uB"],
            ),
            agent_kp.public_key_jwk,
        )
        graph.add_authorship(
            authorship_credential(
                agent,
                artifact_digest="uB",
                author_class=recursion_mod.CLASS_AUTONOMOUS,
                derived_from=["uA"],
            ),
            agent_kp.public_key_jwk,
        )
        assert graph.human_distance("uA") == recursion_mod.UNBOUNDED

    def test_a_forged_witness_is_caught_by_recomputation(self):
        graph, _, _, _, _ = self._chain(3)
        operator_kp, operator = identity("operator.example.com")
        step = step_credential(operator, step_id="run-3", inputs=["uGEN3"], graph=graph, bound=2)
        subject = dict(step["credentialSubject"])
        subject["humanDistanceWitness"] = {"uGEN3": 1}
        subject["maxHumanDistance"] = 1
        forged = dict(step)
        forged["credentialSubject"] = subject
        assert recursion_mod.REASON_INVALID_PROOF in check_step(
            forged, operator_kp.public_key_jwk, graph
        )

    def test_a_human_key_must_be_held_under_presence(self):
        _, human = identity("reviewer.example.com")
        with pytest.raises(PacingError):
            authorship_credential(
                human,
                artifact_digest="uX",
                author_class=recursion_mod.CLASS_HUMAN,
                custody_class=recursion_mod.CUSTODY_SOFTWARE,
            )

    def test_class_bounds_tighten_specific_artifact_classes(self):
        graph, _, _, agent_kp, agent = self._chain(1)
        operator_kp, operator = identity("operator.example.com")
        graph.add_authorship(
            authorship_credential(
                agent,
                artifact_digest="uEVAL",
                author_class=recursion_mod.CLASS_AUTONOMOUS,
                derived_from=["uGEN1"],
                artifact_class="evaluation",
            ),
            agent_kp.public_key_jwk,
        )
        step = step_credential(
            operator,
            step_id="run-4",
            inputs=["uEVAL"],
            graph=graph,
            bound=5,
            class_bounds={"evaluation": 1},
        )
        assert recursion_mod.REASON_BOUND_EXCEEDED in check_step(
            step, operator_kp.public_key_jwk, graph
        )


# ---------------------------------------------------------------------------
# PAD-127: pre-registered development step
# ---------------------------------------------------------------------------


class TestPreRegistration:
    CONFIG = {"scale": "tier-3", "objective": "lm", "dataRoot": "uDATA"}
    PLAN = {"evaluations": ["cyber", "bio", "autonomy"], "thresholds": {"cyber": 0.4}}

    def _registered(self, operator, peer_did, min_seconds=3600):
        return register_step(
            operator,
            step_id="run-77",
            configuration=self.CONFIG,
            evaluation_plan=self.PLAN,
            min_seconds=min_seconds,
            objection_authorities=[peer_did],
            opens_at=T0,
        )

    def test_admits_only_after_the_window(self):
        operator_kp, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        registration = self._registered(operator, peer.get_did())
        execution = issue_execution(operator, registration=registration, log_index=41)
        assert (
            check_admission(
                execution,
                registration,
                self.CONFIG,
                operator_kp.public_key_jwk,
                now=T0 + timedelta(hours=2),
            )
            is None
        )
        assert (
            check_admission(
                execution,
                registration,
                self.CONFIG,
                operator_kp.public_key_jwk,
                now=T0 + timedelta(minutes=5),
            )
            == prereg_mod.REASON_WINDOW_NOT_ELAPSED
        )

    def test_a_different_workload_is_refused_at_the_scheduler(self):
        operator_kp, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        registration = self._registered(operator, peer.get_did())
        execution = issue_execution(operator, registration=registration)
        swapped = dict(self.CONFIG)
        swapped["scale"] = "tier-4"
        assert (
            check_admission(
                execution,
                registration,
                swapped,
                operator_kp.public_key_jwk,
                now=T0 + timedelta(hours=2),
            )
            == prereg_mod.REASON_CONFIG_MISMATCH
        )

    def test_a_named_authority_can_block(self):
        operator_kp, operator = identity("operator.example.com")
        peer_kp, peer = identity("institute.example.org")
        registration = self._registered(operator, peer.get_did())
        execution = issue_execution(operator, registration=registration)
        objection = object_to_step(
            peer, registration=registration, reason_code="above-agreed-ceiling"
        )
        assert (
            check_admission(
                execution,
                registration,
                self.CONFIG,
                operator_kp.public_key_jwk,
                objections=[objection],
                objection_public_keys={peer.get_did(): peer_kp.public_key_jwk},
                now=T0 + timedelta(hours=2),
            )
            == prereg_mod.REASON_OBJECTED
        )

    def test_an_unnamed_party_cannot_block(self):
        operator_kp, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        rogue_kp, rogue = identity("rogue.example.net")
        registration = self._registered(operator, peer.get_did())
        execution = issue_execution(operator, registration=registration)
        objection = object_to_step(rogue, registration=registration, reason_code="noise")
        assert (
            check_admission(
                execution,
                registration,
                self.CONFIG,
                operator_kp.public_key_jwk,
                objections=[objection],
                objection_public_keys={rogue.get_did(): rogue_kp.public_key_jwk},
                now=T0 + timedelta(hours=2),
            )
            is None
        )

    def test_a_window_is_mandatory(self):
        _, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        with pytest.raises(PacingError):
            register_step(
                operator,
                step_id="run-x",
                configuration=self.CONFIG,
                evaluation_plan=self.PLAN,
                min_seconds=0,
                objection_authorities=[peer.get_did()],
            )

    def test_results_are_checked_against_the_committed_plan(self):
        operator_kp, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        registration = self._registered(operator, peer.get_did())
        faithful = publish_results(
            operator,
            registration=registration,
            results={"cyber": 0.3, "bio": 0.1, "autonomy": 4.0},
        )
        assert check_results(faithful, registration, operator_kp.public_key_jwk) == []
        selective = publish_results(
            operator, registration=registration, results={"cyber": 0.3, "surprise": 1.0}
        )
        divergences = check_results(selective, registration, operator_kp.public_key_jwk)
        assert prereg_mod.REASON_EVAL_ADDED in divergences
        assert prereg_mod.REASON_EVAL_OMITTED in divergences

    def test_a_plan_needs_at_least_one_evaluation(self):
        _, operator = identity("operator.example.com")
        _, peer = identity("institute.example.org")
        with pytest.raises(PacingError):
            register_step(
                operator,
                step_id="run-y",
                configuration=self.CONFIG,
                evaluation_plan={"evaluations": []},
                min_seconds=60,
                objection_authorities=[peer.get_did()],
            )


# ---------------------------------------------------------------------------
# PAD-128: double-entry compute custody
# ---------------------------------------------------------------------------


class TestComputeCustody:
    def _books(self, envelope=100, ceiling=60):
        operator_kp, operator = identity("operator.example.com")
        provider_kp, provider = identity("cloud.example.net")
        mandate = compute_mandate(
            operator,
            operator_did=operator.get_did(),
            period="2026-Q3",
            envelope=envelope,
            per_workload_ceiling=ceiling,
        )
        controller = AdmissionController(
            mandate=mandate,
            mandate_public_key=operator_kp.public_key_jwk,
            provider_did=provider.get_did(),
        )
        return operator_kp, operator, provider_kp, provider, mandate, controller

    def test_agreeing_books_reconcile_clean(self):
        operator_kp, operator, provider_kp, provider, mandate, controller = self._books()
        first, _ = controller.admit(provider, workload_id="w1", period="2026-Q3", magnitude=50)
        second, _ = controller.admit(provider, workload_id="w2", period="2026-Q3", magnitude=40)
        ledger = declared_ledger(
            operator,
            period="2026-Q3",
            entries=[
                {"workload": "w1", "magnitude": 50},
                {"workload": "w2", "magnitude": 40},
            ],
            mandate=mandate,
        )
        assert (
            reconcile(
                ledger=ledger,
                receipts=[first, second],
                operator_public_key=operator_kp.public_key_jwk,
                provider_public_keys={provider.get_did(): provider_kp.public_key_jwk},
                mandate=mandate,
            )
            == []
        )

    def test_an_undeclared_workload_surfaces_from_the_provider_side(self):
        operator_kp, operator, provider_kp, provider, mandate, controller = self._books()
        first, _ = controller.admit(provider, workload_id="w1", period="2026-Q3", magnitude=50)
        second, _ = controller.admit(provider, workload_id="w2", period="2026-Q3", magnitude=40)
        ledger = declared_ledger(
            operator,
            period="2026-Q3",
            entries=[{"workload": "w1", "magnitude": 50}],
            mandate=mandate,
        )
        divergences = reconcile(
            ledger=ledger,
            receipts=[first, second],
            operator_public_key=operator_kp.public_key_jwk,
            provider_public_keys={provider.get_did(): provider_kp.public_key_jwk},
            mandate=mandate,
        )
        assert [item.kind for item in divergences] == [custody_mod.DIVERGENCE_UNDECLARED_ALLOCATION]
        assert divergences[0].workload == "w2"
        assert divergences[0].provider == provider.get_did()

    def test_an_unbacked_declaration_surfaces_too(self):
        operator_kp, operator, provider_kp, provider, mandate, controller = self._books()
        first, _ = controller.admit(provider, workload_id="w1", period="2026-Q3", magnitude=50)
        ledger = declared_ledger(
            operator,
            period="2026-Q3",
            entries=[
                {"workload": "w1", "magnitude": 50},
                {"workload": "ghost", "magnitude": 5},
            ],
            mandate=mandate,
        )
        divergences = reconcile(
            ledger=ledger,
            receipts=[first],
            operator_public_key=operator_kp.public_key_jwk,
            provider_public_keys={provider.get_did(): provider_kp.public_key_jwk},
            mandate=mandate,
        )
        assert [item.kind for item in divergences] == [custody_mod.DIVERGENCE_UNBACKED_DECLARATION]

    def test_magnitude_mismatch_is_typed_and_attributable(self):
        operator_kp, operator, provider_kp, provider, mandate, controller = self._books()
        first, _ = controller.admit(provider, workload_id="w1", period="2026-Q3", magnitude=50)
        ledger = declared_ledger(
            operator,
            period="2026-Q3",
            entries=[{"workload": "w1", "magnitude": 5}],
            mandate=mandate,
        )
        divergences = reconcile(
            ledger=ledger,
            receipts=[first],
            operator_public_key=operator_kp.public_key_jwk,
            provider_public_keys={provider.get_did(): provider_kp.public_key_jwk},
            mandate=mandate,
        )
        assert divergences[0].kind == custody_mod.DIVERGENCE_MAGNITUDE_MISMATCH
        assert divergences[0].declared_magnitude == 5
        assert divergences[0].allocated_magnitude == 50

    def test_envelope_and_ceiling_are_enforced_at_admission(self):
        _, _, _, provider, _, controller = self._books(envelope=100, ceiling=60)
        assert (
            controller.admit(provider, workload_id="big", period="2026-Q3", magnitude=70)[1]
            == custody_mod.REASON_CEILING_EXCEEDED
        )
        controller.admit(provider, workload_id="w1", period="2026-Q3", magnitude=60)
        assert (
            controller.admit(provider, workload_id="w2", period="2026-Q3", magnitude=50)[1]
            == custody_mod.REASON_ENVELOPE_EXCEEDED
        )

    def test_a_receipt_signed_by_the_wrong_party_is_rejected(self):
        operator_kp, operator, _, provider, mandate, controller = self._books()
        forger_kp, forger = identity("forger.example.net")
        forged, _ = controller.admit(forger, workload_id="w1", period="2026-Q3", magnitude=10)
        ledger = declared_ledger(
            operator,
            period="2026-Q3",
            entries=[{"workload": "w1", "magnitude": 10}],
            mandate=mandate,
        )
        divergences = reconcile(
            ledger=ledger,
            receipts=[forged],
            operator_public_key=operator_kp.public_key_jwk,
            provider_public_keys={provider.get_did(): None},
            mandate=mandate,
        )
        assert custody_mod.DIVERGENCE_INVALID_ENTRY in [item.kind for item in divergences]


# ---------------------------------------------------------------------------
# PAD-129: graduated multilateral pace control
# ---------------------------------------------------------------------------


class TestPaceControl:
    def _quorum(self, count=7, minimum=5):
        holders = [identity("holder%d.example.org" % index) for index in range(count)]
        policy = QuorumPolicy(
            holders=tuple(signer.get_did() for _, signer in holders), minimum=minimum
        )
        keys = {signer.get_did(): kp.public_key_jwk for kp, signer in holders}
        return holders, policy, keys

    def test_quorum_is_required(self):
        holders, policy, keys = self._quorum()
        record = pace_epoch(epoch=7, pace_lambda=1.0 / 3600, effective_from=T0)
        endorsements = [endorse_epoch(signer, record) for _, signer in holders[:5]]
        assert verify_epoch(record, endorsements, policy, keys) == []
        assert pace_mod.REASON_QUORUM_NOT_MET in verify_epoch(
            record, endorsements[:4], policy, keys
        )

    def test_one_holder_cannot_actuate_alone(self):
        holders, policy, keys = self._quorum()
        record = pace_epoch(epoch=8, pace_lambda=0.5, effective_from=T0)
        single = [endorse_epoch(holders[0][1], record)]
        assert pace_mod.REASON_QUORUM_NOT_MET in verify_epoch(record, single, policy, keys)

    def test_the_same_holder_cannot_count_twice(self):
        holders, policy, keys = self._quorum(count=3, minimum=2)
        record = pace_epoch(epoch=9, pace_lambda=0.5, effective_from=T0)
        doubled = [endorse_epoch(holders[0][1], record) for _ in range(2)]
        reasons = verify_epoch(record, doubled, policy, keys)
        assert pace_mod.REASON_DUPLICATE_HOLDER in reasons
        assert pace_mod.REASON_QUORUM_NOT_MET in reasons

    def test_an_endorsement_of_a_different_record_does_not_count(self):
        holders, policy, keys = self._quorum(count=3, minimum=2)
        record = pace_epoch(epoch=10, pace_lambda=0.5, effective_from=T0)
        other = pace_epoch(epoch=10, pace_lambda=0.0, effective_from=T0)
        endorsements = [endorse_epoch(signer, other) for _, signer in holders[:2]]
        assert pace_mod.REASON_DIGEST_MISMATCH in verify_epoch(record, endorsements, policy, keys)

    def test_a_non_holder_endorsement_is_ignored(self):
        holders, policy, keys = self._quorum(count=3, minimum=2)
        outsider_kp, outsider = identity("outsider.example.net")
        record = pace_epoch(epoch=11, pace_lambda=0.5, effective_from=T0)
        keys[outsider.get_did()] = outsider_kp.public_key_jwk
        endorsements = [endorse_epoch(outsider, record), endorse_epoch(holders[0][1], record)]
        reasons = verify_epoch(record, endorsements, policy, keys)
        assert pace_mod.REASON_NOT_A_HOLDER in reasons

    def test_authority_contracts_in_order_of_consequence(self):
        rate = 1.0 / 3600
        at_zero = pace_mod.effective_standing(
            anchored_at=T0, initial_standing=1.0, pace_lambda=rate, at_time=T0
        )
        at_one_hour = pace_mod.effective_standing(
            anchored_at=T0,
            initial_standing=1.0,
            pace_lambda=rate,
            at_time=T0 + timedelta(hours=1),
        )
        at_two_hours = pace_mod.effective_standing(
            anchored_at=T0,
            initial_standing=1.0,
            pace_lambda=rate,
            at_time=T0 + timedelta(hours=2),
        )
        assert permitted_classes(at_zero) == list(pace_mod.CONSEQUENCE_ORDER)
        assert permitted_classes(at_one_hour) == [pace_mod.CLASS_ROUTINE]
        assert permitted_classes(at_two_hours) == []

    def test_a_higher_rate_shortens_every_half_life(self):
        assert pace_mod.half_life_seconds(1.0 / 3600) > pace_mod.half_life_seconds(1.0 / 600)

    def test_an_older_slower_epoch_cannot_be_replayed(self):
        slow = pace_epoch(epoch=5, pace_lambda=0.0, effective_from=T0)
        fast = pace_epoch(epoch=6, pace_lambda=1.0, effective_from=T0)
        chosen = select_epoch([slow, fast], at_time=T0 + timedelta(hours=1))
        assert chosen["epoch"] == 6
        assert select_epoch([slow], at_time=T0 + timedelta(hours=1), floor_epoch=6) is None

    def test_a_future_epoch_is_not_yet_in_force(self):
        future = pace_epoch(epoch=9, pace_lambda=1.0, effective_from=T0 + timedelta(days=1))
        assert select_epoch([future], at_time=T0) is None

    def test_silence_contracts_rather_than_preserves(self):
        record = pace_epoch(epoch=3, pace_lambda=0.001, effective_from=T0)
        stale = pace_mod.effective_lambda(
            record,
            last_observed=T0,
            max_age_seconds=600,
            stale_lambda=0.05,
            at_time=T0 + timedelta(hours=5),
        )
        assert stale == 0.05
        fresh = pace_mod.effective_lambda(
            record,
            last_observed=T0 + timedelta(hours=5),
            max_age_seconds=600,
            stale_lambda=0.05,
            at_time=T0 + timedelta(hours=5),
        )
        assert fresh == 0.001

    def test_class_overrides_apply_different_rates(self):
        record = pace_epoch(
            epoch=4,
            pace_lambda=0.001,
            effective_from=T0,
            class_overrides={pace_mod.CLASS_IRREVERSIBLE: 0.9},
        )
        assert (
            pace_mod.effective_lambda(record, consequence_class=pace_mod.CLASS_IRREVERSIBLE) == 0.9
        )
        assert pace_mod.effective_lambda(record, consequence_class=pace_mod.CLASS_ROUTINE) == 0.001

    def test_the_record_names_no_subject(self):
        record = pace_epoch(epoch=1, pace_lambda=0.1, effective_from=T0)
        assert "id" not in record
        assert "subject" not in record

    def test_a_quorum_minimum_above_the_holder_count_is_refused(self):
        with pytest.raises(PacingError):
            QuorumPolicy(holders=("a", "b"), minimum=3)


# ---------------------------------------------------------------------------
# PAD-130: capability-proportional sequential delay
# ---------------------------------------------------------------------------


class TestSequentialDelay:
    PARAMS = {"baseSteps": 200, "stepsPerUnit": 400.0, "exponent": 1.5, "maxSteps": 50000}

    def test_required_interval_is_monotone_in_the_increment(self):
        steps = [fuse_mod.required_steps(delta, self.PARAMS) for delta in (0, 0.5, 1, 2, 4)]
        assert steps == sorted(steps)
        assert steps[0] == 200
        assert steps[-1] > steps[0]

    def test_a_bigger_leap_costs_a_longer_fuse(self):
        small = fuse_mod.required_steps(0.5, self.PARAMS)
        large = fuse_mod.required_steps(3.0, self.PARAMS)
        assert large > small * 3

    def test_the_seed_cannot_be_known_before_registration(self):
        first = fuse_mod.derive_seed("uROOT-A", "uREG-1")
        assert first != fuse_mod.derive_seed("uROOT-B", "uREG-1")
        assert first != fuse_mod.derive_seed("uROOT-A", "uREG-2")

    def test_a_valid_advancement_verifies(self):
        keypair, operator = identity("operator.example.com")
        function = CheckpointedHashChain(checkpoint_interval=100)
        credential = advancement_credential(
            operator,
            step_id="adv-1",
            increment=1.0,
            reference_point=0.3,
            measurement=1.3,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )
        assert (
            check_advancement(
                credential,
                keypair.public_key_jwk,
                log_root="uROOT",
                registration_digest="uREG",
                parameters=self.PARAMS,
                function=function,
            )
            == []
        )

    def test_a_proof_for_a_different_seed_is_refused(self):
        keypair, operator = identity("operator.example.com")
        function = CheckpointedHashChain(checkpoint_interval=100)
        credential = advancement_credential(
            operator,
            step_id="adv-2",
            increment=0.5,
            reference_point=0.3,
            measurement=0.8,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )
        reasons = check_advancement(
            credential,
            keypair.public_key_jwk,
            log_root="uDIFFERENT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )
        assert fuse_mod.REASON_SEED_MISMATCH in reasons
        assert fuse_mod.REASON_DELAY_PROOF_INVALID in reasons

    def test_understating_the_increment_breaks_the_signature(self):
        keypair, operator = identity("operator.example.com")
        function = CheckpointedHashChain(checkpoint_interval=100)
        credential = advancement_credential(
            operator,
            step_id="adv-3",
            increment=2.0,
            reference_point=0.0,
            measurement=2.0,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )
        subject = dict(credential["credentialSubject"])
        subject["increment"] = 0.1
        subject["requiredSteps"] = fuse_mod.required_steps(0.1, self.PARAMS)
        tampered = dict(credential)
        tampered["credentialSubject"] = subject
        assert fuse_mod.REASON_INVALID_PROOF in check_advancement(
            tampered,
            keypair.public_key_jwk,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )

    def test_a_short_evaluation_does_not_satisfy_a_large_increment(self):
        keypair, operator = identity("operator.example.com")
        function = CheckpointedHashChain(checkpoint_interval=100)
        credential = advancement_credential(
            operator,
            step_id="adv-4",
            increment=0.1,
            reference_point=0.0,
            measurement=0.1,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=self.PARAMS,
            function=function,
        )
        assert (
            check_advancement(
                credential,
                keypair.public_key_jwk,
                log_root="uROOT",
                registration_digest="uREG",
                parameters=self.PARAMS,
                function=function,
                expected_increment=0.1,
            )
            == []
        )
        stricter = dict(self.PARAMS)
        stricter["baseSteps"] = 10_000
        assert fuse_mod.REASON_STEPS_INSUFFICIENT in check_advancement(
            credential,
            keypair.public_key_jwk,
            log_root="uROOT",
            registration_digest="uREG",
            parameters=stricter,
            function=function,
        )

    def test_the_chain_rejects_a_forged_output(self):
        function = CheckpointedHashChain(checkpoint_interval=50)
        seed = fuse_mod.derive_seed("uROOT", "uREG")
        proof = function.evaluate(seed, 200)
        assert function.verify(seed, 200, proof)
        forged = dict(proof)
        forged["output"] = "uAAAA"
        assert function.verify(seed, 200, forged) is False

    def test_checkpoints_must_be_consistent(self):
        function = CheckpointedHashChain(checkpoint_interval=50)
        seed = fuse_mod.derive_seed("uROOT", "uREG")
        proof = function.evaluate(seed, 200)
        forged = dict(proof)
        forged["checkpoints"] = list(proof["checkpoints"])
        forged["checkpoints"][0] = "uBBBB"
        assert function.verify(seed, 200, forged) is False

    def test_stage_release_widens_with_cumulative_evidence(self):
        stages = [
            {"class": "internal", "steps": 200},
            {"class": "partner", "steps": 500},
            {"class": "public", "steps": 5000},
        ]
        assert fuse_mod.stage_unlock(600, stages) == ["internal", "partner"]
        assert fuse_mod.stage_unlock(100, stages) == []


# ---------------------------------------------------------------------------
# PAD-131: immutable red line commitment
# ---------------------------------------------------------------------------


class TestRedLines:
    def _policy(self):
        return commit_policy(
            [
                Threshold("cyber", "cyber-uplift", ">=", 0.40, redline_mod.CONSEQUENCE_HALT),
                Threshold("bio", "bio-uplift", ">=", 0.25, redline_mod.CONSEQUENCE_HALT),
                Threshold("autonomy", "autonomy-days", ">=", 30.0, redline_mod.CONSEQUENCE_NARROW),
            ]
        )

    def test_a_committed_threshold_opens_and_verifies(self):
        keypair, operator = identity("operator.example.com")
        commitment = self._policy()
        published = publish_policy(operator, commitment, log_index=100)
        reveal = open_threshold(commitment, "cyber")
        assert verify_open(reveal, published, keypair.public_key_jwk) == []

    def test_the_published_record_discloses_no_threshold(self):
        _, operator = identity("operator.example.com")
        commitment = self._policy()
        published = publish_policy(operator, commitment, log_index=100)
        assert "cyber-uplift" not in str(published)
        assert published["credentialSubject"]["cardinality"] == 3

    def test_a_relaxed_threshold_does_not_open(self):
        keypair, operator = identity("operator.example.com")
        commitment = self._policy()
        published = publish_policy(operator, commitment, log_index=100)
        reveal = open_threshold(commitment, "cyber")
        forged = dict(reveal)
        forged["threshold"] = dict(reveal["threshold"])
        forged["threshold"]["value"] = 0.95
        assert redline_mod.REASON_INCLUSION_FAILED in verify_open(
            forged, published, keypair.public_key_jwk
        )

    def test_ordering_comes_from_the_log_not_the_clock(self):
        operator_kp, operator = identity("operator.example.com")
        evaluator_kp, evaluator = identity("evaluator.example.org")
        commitment = self._policy()
        published = publish_policy(operator, commitment, log_index=100)
        measurement = measurement_record(
            evaluator,
            measurement="cyber-uplift",
            value=0.52,
            subject_of_measurement="model-x",
            log_index=140,
        )
        assert (
            check_ordering(
                published, measurement, operator_kp.public_key_jwk, evaluator_kp.public_key_jwk
            )
            == []
        )
        late = publish_policy(
            operator,
            commit_policy([Threshold("cyber", "cyber-uplift", ">=", 0.95, "halt")]),
            log_index=200,
            supersedes=commitment.root,
            supersedes_index=100,
        )
        assert redline_mod.REASON_ORDER_VIOLATION in check_ordering(
            late, measurement, operator_kp.public_key_jwk, evaluator_kp.public_key_jwk
        )

    def test_an_amendment_chain_must_be_complete_and_ordered(self):
        keypair, operator = identity("operator.example.com")
        first = self._policy()
        second = commit_policy([Threshold("cyber", "cyber-uplift", ">=", 0.35, "halt")])
        published_first = publish_policy(operator, first, log_index=100)
        published_second = publish_policy(
            operator, second, log_index=200, supersedes=first.root, supersedes_index=100
        )
        assert (
            verify_amendment_chain([published_first, published_second], keypair.public_key_jwk)
            == []
        )
        orphan = publish_policy(operator, second, log_index=300, supersedes="uWRONG")
        assert redline_mod.REASON_CHAIN_BROKEN in verify_amendment_chain(
            [published_first, orphan], keypair.public_key_jwk
        )

    def test_an_amendment_cannot_be_backdated_in_the_log(self):
        keypair, operator = identity("operator.example.com")
        first = self._policy()
        second = commit_policy([Threshold("cyber", "cyber-uplift", ">=", 0.35, "halt")])
        published_first = publish_policy(operator, first, log_index=200)
        backdated = publish_policy(
            operator, second, log_index=100, supersedes=first.root, supersedes_index=200
        )
        assert redline_mod.REASON_CHAIN_BROKEN in verify_amendment_chain(
            [published_first, backdated], keypair.public_key_jwk
        )

    def test_a_threshold_knows_when_it_is_crossed(self):
        threshold = Threshold("cyber", "cyber-uplift", ">=", 0.40, "halt")
        assert threshold.crossed(0.52) is True
        assert threshold.crossed(0.10) is False

    def test_distinct_names_are_required(self):
        with pytest.raises(PacingError):
            commit_policy(
                [
                    Threshold("cyber", "a", ">=", 1.0, "halt"),
                    Threshold("cyber", "b", ">=", 2.0, "halt"),
                ]
            )


# ---------------------------------------------------------------------------
# PAD-132: oversight ratio bound
# ---------------------------------------------------------------------------


class TestOversightRatio:
    def _receipts(self):
        internal_kp, internal = identity("safety.operator.example.com")
        external_kp, external = identity("redteam.example.org")
        keys = {
            internal.get_did(): internal_kp.public_key_jwk,
            external.get_did(): external_kp.public_key_jwk,
        }
        artifacts = ["uART1", "uART2"]
        receipts = [
            oversight_receipt(
                internal,
                work_class=oversight_mod.WORK_INTERPRETABILITY,
                measure=40,
                period="P1",
                artifact_digests=artifacts,
                nonce="n1",
            ),
            oversight_receipt(
                external,
                work_class=oversight_mod.WORK_ADVERSARIAL,
                measure=30,
                period="P1",
                artifact_digests=["uART1"],
                nonce="n2",
                independence=oversight_mod.INDEPENDENCE_EXTERNAL,
            ),
        ]
        return keys, artifacts, receipts

    def test_the_ratio_gates_the_step(self):
        keys, artifacts, receipts = self._receipts()
        accumulation = accumulate(receipts, step_artifacts=artifacts, period="P1", public_keys=keys)
        assert check_ratio(compute_measure=1000, accumulation=accumulation, ratio=0.05) == []
        assert oversight_mod.REASON_RATIO_NOT_MET in check_ratio(
            compute_measure=1000, accumulation=accumulation, ratio=0.20
        )

    def test_oversight_on_other_artifacts_does_not_count(self):
        keys, artifacts, receipts = self._receipts()
        internal_kp, internal = identity("other.example.com")
        keys[internal.get_did()] = internal_kp.public_key_jwk
        elsewhere = oversight_receipt(
            internal,
            work_class=oversight_mod.WORK_INTERPRETABILITY,
            measure=1000,
            period="P1",
            artifact_digests=["uSOMETHING-ELSE"],
            nonce="n9",
        )
        accumulation = accumulate(
            receipts + [elsewhere], step_artifacts=artifacts, period="P1", public_keys=keys
        )
        assert oversight_mod.REASON_NO_ARTIFACT_OVERLAP in accumulation.skipped
        assert accumulation.total < 1000

    def test_the_same_work_cannot_be_spent_twice(self):
        keys, artifacts, receipts = self._receipts()
        _, operator = identity("operator.example.com")
        ledger = NonceLedger()
        first = accumulate(
            receipts, step_artifacts=artifacts, period="P1", public_keys=keys, ledger=ledger
        )
        authorize_step(
            operator,
            step_id="s1",
            compute_measure=1000,
            accumulation=first,
            ratio=0.05,
            ledger=ledger,
        )
        second = accumulate(
            receipts, step_artifacts=artifacts, period="P1", public_keys=keys, ledger=ledger
        )
        assert second.total < first.total
        assert oversight_mod.REASON_RECEIPT_CONSUMED in second.skipped

    def test_per_class_floors_prevent_satisfying_the_bound_from_one_class(self):
        keys, artifacts, receipts = self._receipts()
        accumulation = accumulate(receipts, step_artifacts=artifacts, period="P1", public_keys=keys)
        assert oversight_mod.REASON_FLOOR_NOT_MET in check_ratio(
            compute_measure=1000,
            accumulation=accumulation,
            ratio=0.05,
            class_floors={oversight_mod.WORK_HUMAN_REVIEW: 5.0},
        )

    def test_external_work_is_weighted_above_internal(self):
        keys, artifacts, receipts = self._receipts()
        accumulation = accumulate(receipts, step_artifacts=artifacts, period="P1", public_keys=keys)
        assert accumulation.by_class[oversight_mod.WORK_ADVERSARIAL] == 45.0

    def test_a_forged_receipt_is_a_finding(self):
        keys, artifacts, receipts = self._receipts()
        _, forger = identity("forger.example.net")
        forged = oversight_receipt(
            forger,
            work_class=oversight_mod.WORK_INTERPRETABILITY,
            measure=100000,
            period="P1",
            artifact_digests=artifacts,
            nonce="nX",
        )
        accumulation = accumulate(
            receipts + [forged], step_artifacts=artifacts, period="P1", public_keys=keys
        )
        assert oversight_mod.REASON_INVALID_PROOF in accumulation.reasons

    def test_authorization_refuses_when_the_predicate_fails(self):
        keys, artifacts, receipts = self._receipts()
        _, operator = identity("operator.example.com")
        accumulation = accumulate(receipts, step_artifacts=artifacts, period="P1", public_keys=keys)
        with pytest.raises(PacingError):
            authorize_step(
                operator,
                step_id="s2",
                compute_measure=100000,
                accumulation=accumulation,
                ratio=0.5,
            )


# ---------------------------------------------------------------------------
# PAD-133: weight-bound load authorization
# ---------------------------------------------------------------------------


class TestLoadAuthorization:
    TENSORS = [("layer0.weight", b"\x01" * 64), ("layer1.weight", b"\x02" * 64)]

    def _authorized(self, decay=1.0 / 3600):
        holders = [identity("holder%d.example.org" % index) for index in range(5)]
        policy = QuorumPolicy(holders=tuple(signer.get_did() for _, signer in holders), minimum=3)
        keys = {signer.get_did(): kp.public_key_jwk for kp, signer in holders}
        identifier = identifier_for(self.TENSORS)
        record = load_authorization(
            weight_identifier=identifier,
            envelope={
                "maxRequestsPerMinute": 1000,
                "maxConsequenceClass": pace_mod.CLASS_IRREVERSIBLE,
                "interfaces": ["api", "batch"],
            },
            decay_lambda=decay,
            anchored_at=T0,
            runtime_classes=["attested-runtime"],
        )
        endorsements = [endorse_authorization(signer, record) for _, signer in holders[:3]]
        return holders, policy, keys, record, endorsements

    def test_the_parameters_name_themselves(self):
        first = identifier_for(self.TENSORS)
        assert first.startswith("urn:vouch:weights:")
        assert first == identifier_for(list(reversed(self.TENSORS)))

    def test_one_flipped_byte_yields_a_different_identifier(self):
        modified = [("layer0.weight", b"\x01" * 63 + b"\x09"), ("layer1.weight", b"\x02" * 64)]
        assert identifier_for(modified) != identifier_for(self.TENSORS)

    def test_a_current_authorization_admits_the_load(self):
        _, policy, keys, record, endorsements = self._authorized()
        decision = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_IRREVERSIBLE,
            at_time=T0,
            runtime_class="attested-runtime",
        )
        assert decision.admitted is True
        assert decision.envelope["maxRequestsPerMinute"] == 1000

    def test_an_authorization_does_not_transfer_to_modified_parameters(self):
        _, policy, keys, record, endorsements = self._authorized()
        modified = [("layer0.weight", b"\x01" * 63 + b"\x09"), ("layer1.weight", b"\x02" * 64)]
        decision = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=modified,
            deployment_class=pace_mod.CLASS_ROUTINE,
            at_time=T0,
            runtime_class="attested-runtime",
        )
        assert decision.admitted is False
        assert load_mod.REASON_IDENTIFIER_MISMATCH in decision.reasons

    def test_the_envelope_narrows_as_the_authorization_ages(self):
        _, policy, keys, record, endorsements = self._authorized()
        later = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_ROUTINE,
            at_time=T0 + timedelta(hours=1),
            runtime_class="attested-runtime",
        )
        assert later.admitted is True
        assert later.envelope["maxRequestsPerMinute"] < 1000
        assert later.envelope["maxConsequenceClass"] == pace_mod.CLASS_ROUTINE

    def test_a_high_consequence_load_stops_first(self):
        _, policy, keys, record, endorsements = self._authorized()
        decision = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_IRREVERSIBLE,
            at_time=T0 + timedelta(hours=1),
            runtime_class="attested-runtime",
        )
        assert decision.admitted is False
        assert load_mod.REASON_STANDING_TOO_LOW in decision.reasons

    def test_a_pace_epoch_reaches_resident_parameters(self):
        _, policy, keys, record, endorsements = self._authorized(decay=0.0)
        without = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_IRREVERSIBLE,
            at_time=T0 + timedelta(hours=4),
            runtime_class="attested-runtime",
        )
        assert without.admitted is True
        with_epoch = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_IRREVERSIBLE,
            at_time=T0 + timedelta(hours=4),
            pace_lambda=1.0 / 3600,
            runtime_class="attested-runtime",
        )
        assert with_epoch.admitted is False

    def test_a_short_quorum_does_not_authorize(self):
        _, policy, keys, record, endorsements = self._authorized()
        decision = check_load(
            record=record,
            endorsements=endorsements[:2],
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_ROUTINE,
            at_time=T0,
            runtime_class="attested-runtime",
        )
        assert load_mod.REASON_QUORUM_NOT_MET in decision.reasons

    def test_an_unattested_runtime_is_refused(self):
        _, policy, keys, record, endorsements = self._authorized()
        decision = check_load(
            record=record,
            endorsements=endorsements,
            policy=policy,
            holder_public_keys=keys,
            tensors=self.TENSORS,
            deployment_class=pace_mod.CLASS_ROUTINE,
            at_time=T0,
            runtime_class="unknown-runtime",
        )
        assert load_mod.REASON_RUNTIME_NOT_ATTESTED in decision.reasons

    def test_a_derived_envelope_never_expands(self):
        envelope = {
            "maxRequestsPerMinute": 100,
            "maxConsequenceClass": pace_mod.CLASS_ELEVATED,
            "interfaces": ["api"],
        }
        derived = attenuate_envelope(envelope, 0.5)
        assert is_attenuation(derived, envelope) is True
        widened = dict(derived)
        widened["maxRequestsPerMinute"] = 500
        assert is_attenuation(widened, envelope) is False
        escalated = dict(derived)
        escalated["maxConsequenceClass"] = pace_mod.CLASS_IRREVERSIBLE
        assert is_attenuation(escalated, envelope) is False
        extra = dict(derived)
        extra["newCapability"] = True
        assert is_attenuation(extra, envelope) is False


# ---------------------------------------------------------------------------
# PAD-134: sealed dissent registration
# ---------------------------------------------------------------------------


class TestSealedDissent:
    def _registered(self, conditions=None, threshold=None, time_lock=None):
        private, public = escrow_keypair()
        salt = secrets.token_bytes(32)
        concern = concern_object(
            subject_descriptor="scaling-decision-tier-4",
            statement="The evaluation plan omits the autonomy horizon measure.",
            evidence_anchors={"plan": "uPLAN1"},
            release_conditions=conditions or [dissent_author()],
            corroboration_threshold=threshold,
            time_lock=time_lock,
        )
        registration = register_concern(concern, escrow_public_key=public, registry_salt=salt)
        return private, public, salt, concern, registration

    def test_the_registry_entry_discloses_nothing(self):
        _, _, _, concern, registration = self._registered()
        entry = registration.log_entry()
        assert sorted(entry) == ["commitment", "sealed", "subjectTag"]
        assert "scaling-decision" not in str(entry)
        assert "autonomy horizon" not in str(entry)

    def test_the_escrow_can_open_it_and_the_reveal_checks_out(self):
        private, _, _, concern, registration = self._registered()
        entry = registration.log_entry()
        opened = unseal_concern(entry["sealed"], private)
        assert opened == concern
        assert verify_release(opened, registration.blinding, entry) == []

    def test_a_later_reconstruction_does_not_match_the_commitment(self):
        private, _, _, _, registration = self._registered()
        entry = registration.log_entry()
        opened = unseal_concern(entry["sealed"], private)
        rewritten = dict(opened)
        rewritten["statement"] = "Something I thought of after the incident."
        assert verify_release(rewritten, registration.blinding, entry) == ["commitment_mismatch"]

    def test_only_declared_conditions_can_release(self):
        _, _, _, concern, _ = self._registered(conditions=[dissent_author()])
        released, met = evaluate_release(concern, escrow_quorum_released=True, at_time=T0)
        assert released is False
        assert met == []

    def test_corroboration_opens_without_anyone_going_first(self):
        private, public, salt, concern, registration = self._registered(
            conditions=[dissent_author(), "corroboration-threshold"], threshold=3
        )
        entry = registration.log_entry()
        others = [
            register_concern(
                concern_object(
                    subject_descriptor="scaling-decision-tier-4",
                    statement="Same worry, different words %d." % index,
                ),
                escrow_public_key=public,
                registry_salt=salt,
            ).log_entry()
            for index in range(2)
        ]
        released, met = evaluate_release(
            concern,
            tag=registration.subject_tag,
            registry_entries=[entry] + others,
            at_time=T0,
        )
        assert released is True
        assert "corroboration-threshold" in met
        below, _ = evaluate_release(
            concern, tag=registration.subject_tag, registry_entries=[entry], at_time=T0
        )
        assert below is False

    def test_a_time_lock_opens_on_schedule(self):
        _, _, _, concern, registration = self._registered(
            conditions=[dissent_author(), "time-lock-expiry"],
            time_lock=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        assert evaluate_release(concern, at_time=T0)[0] is False
        assert (
            evaluate_release(concern, at_time=datetime(2027, 2, 1, tzinfo=timezone.utc))[0] is True
        )

    def test_a_lapsed_liveness_chain_releases(self):
        _, _, _, concern, _ = self._registered(
            conditions=[dissent_author(), "author-liveness-lapse"]
        )
        chain = LivenessChain()
        first, second = secrets.token_bytes(32), secrets.token_bytes(32)
        assert chain.pulse(first, second, at_time=T0) is True
        assert (
            evaluate_release(
                concern,
                liveness=chain,
                max_gap_seconds=86400,
                at_time=T0 + timedelta(hours=1),
            )[0]
            is False
        )
        assert (
            evaluate_release(
                concern,
                liveness=chain,
                max_gap_seconds=86400,
                at_time=T0 + timedelta(days=10),
            )[0]
            is True
        )

    def test_the_same_subject_tags_alike_and_different_subjects_do_not(self):
        salt = secrets.token_bytes(32)
        from vouch.pacing import subject_tag

        assert subject_tag("subject-a", salt) == subject_tag("subject-a", salt)
        assert subject_tag("subject-a", salt) != subject_tag("subject-b", salt)
        assert subject_tag("subject-a", salt) != subject_tag("subject-a", secrets.token_bytes(32))

    def test_a_weak_escrow_key_is_refused(self):
        concern = concern_object(subject_descriptor="s", statement="t")
        with pytest.raises(PacingError):
            register_concern(concern, escrow_public_key=b"short", registry_salt=b"x" * 32)


def dissent_author():
    """The author-release condition constant, imported lazily for readability."""
    from vouch.pacing.dissent import RELEASE_AUTHOR

    return RELEASE_AUTHOR


# ---------------------------------------------------------------------------
# PAD-135: simultaneous-reveal comparative disclosure
# ---------------------------------------------------------------------------


class TestComparativeDisclosure:
    def _round(self, predicate=disclosure_mod.PREDICATE_ORDERING, mode=None, reference=None):
        parties = {name: identity("%s.example.com" % name) for name in ("alpha", "beta", "gamma")}
        keys = {signer.get_did(): kp.public_key_jwk for kp, signer in parties.values()}
        dids = {name: signer.get_did() for name, (_, signer) in parties.items()}
        convenor_kp, convenor = parties["alpha"]
        descriptor = open_round(
            convenor,
            round_id="r-1",
            participants=list(dids.values()),
            schema={"measure": "autonomy-horizon-days"},
            closing_index=100,
            reveal_index=200,
            predicate=predicate,
            mode=mode or disclosure_mod.MODE_ABSOLUTE,
            reference_value=reference,
        )
        return parties, keys, dids, convenor_kp, descriptor

    def test_nobody_has_to_go_first(self):
        parties, keys, dids, convenor_kp, descriptor = self._round()
        blindings = {name: secrets.token_bytes(32) for name in dids}
        values = {"alpha": 21.0, "beta": 34.0, "gamma": 12.0}
        commitments = [
            commit_measurement(
                parties[name][1],
                descriptor=descriptor,
                value=values[name],
                blinding=blindings[name],
                log_index=50 + index,
            )
            for index, name in enumerate(dids)
        ]
        reveals = [
            reveal_measurement(
                parties[name][1],
                descriptor=descriptor,
                value=values[name],
                blinding=blindings[name],
                log_index=150 + index,
            )
            for index, name in enumerate(dids)
        ]
        state = collect_round(
            descriptor,
            commitments=commitments,
            reveals=reveals,
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=210,
        )
        result = evaluate_predicate(descriptor, state)
        assert result["result"][0] == dids["beta"]
        assert result["gaps"] == [13.0, 9.0]

    def test_a_reveal_must_open_the_commitment(self):
        parties, keys, dids, convenor_kp, descriptor = self._round()
        blinding = secrets.token_bytes(32)
        commitment = commit_measurement(
            parties["beta"][1],
            descriptor=descriptor,
            value=34.0,
            blinding=blinding,
            log_index=50,
        )
        lying = reveal_measurement(
            parties["beta"][1],
            descriptor=descriptor,
            value=99.0,
            blinding=blinding,
            log_index=150,
        )
        state = collect_round(
            descriptor,
            commitments=[commitment],
            reveals=[lying],
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=210,
        )
        assert disclosure_mod.REASON_REVEAL_MISMATCH in state.reasons
        assert state.states[dids["beta"]] == disclosure_mod.STATE_UNREVEALED

    def test_a_late_commitment_is_outside_the_round(self):
        parties, keys, dids, convenor_kp, descriptor = self._round()
        late = commit_measurement(
            parties["gamma"][1],
            descriptor=descriptor,
            value=99.0,
            blinding=secrets.token_bytes(32),
            log_index=120,
        )
        state = collect_round(
            descriptor,
            commitments=[late],
            reveals=[],
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=210,
        )
        assert disclosure_mod.REASON_LATE_COMMITMENT in state.reasons
        assert state.states[dids["gamma"]] == disclosure_mod.STATE_NOT_COMMITTED

    def test_non_participation_is_a_dated_attributable_record(self):
        parties, keys, dids, convenor_kp, descriptor = self._round()
        blinding = secrets.token_bytes(32)
        commitment = commit_measurement(
            parties["alpha"][1],
            descriptor=descriptor,
            value=1.0,
            blinding=blinding,
            log_index=50,
        )
        reveal = reveal_measurement(
            parties["alpha"][1],
            descriptor=descriptor,
            value=1.0,
            blinding=blinding,
            log_index=150,
        )
        state = collect_round(
            descriptor,
            commitments=[commitment],
            reveals=[reveal],
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=210,
        )
        record = closure_record(
            parties["alpha"][1], descriptor=descriptor, state=state, log_size=210
        )
        assert sorted(record["credentialSubject"]["nonCommitters"]) == sorted(
            [dids["beta"], dids["gamma"]]
        )

    def test_the_round_cannot_close_early(self):
        parties, keys, dids, convenor_kp, descriptor = self._round()
        state = collect_round(
            descriptor,
            commitments=[],
            reveals=[],
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=50,
        )
        with pytest.raises(PacingError):
            closure_record(parties["alpha"][1], descriptor=descriptor, state=state, log_size=50)

    def test_the_predicate_is_fixed_before_the_values(self):
        _, _, _, _, descriptor = self._round(predicate=disclosure_mod.PREDICATE_MAXIMUM)
        assert descriptor["credentialSubject"]["predicate"] == disclosure_mod.PREDICATE_MAXIMUM

    def test_ordinal_mode_establishes_standing_without_levels(self):
        parties, keys, dids, convenor_kp, descriptor = self._round(
            predicate=disclosure_mod.PREDICATE_ORDERING,
            mode=disclosure_mod.MODE_ORDINAL,
            reference=30.0,
        )
        blindings = {name: secrets.token_bytes(32) for name in dids}
        differences = {"alpha": -9.0, "beta": 4.0, "gamma": -18.0}
        commitments = [
            commit_measurement(
                parties[name][1],
                descriptor=descriptor,
                value=differences[name],
                blinding=blindings[name],
                log_index=50 + index,
            )
            for index, name in enumerate(dids)
        ]
        reveals = [
            reveal_measurement(
                parties[name][1],
                descriptor=descriptor,
                value=differences[name],
                blinding=blindings[name],
                log_index=150 + index,
            )
            for index, name in enumerate(dids)
        ]
        state = collect_round(
            descriptor,
            commitments=commitments,
            reveals=reveals,
            participant_public_keys=keys,
            convenor_public_key=convenor_kp.public_key_jwk,
            log_size=210,
        )
        result = evaluate_predicate(descriptor, state)
        assert result["result"][0] == dids["beta"]
        assert disclosure_mod.absolute_from_ordinal(descriptor, 4.0) == 34.0

    def test_a_round_needs_two_distinct_participants(self):
        _, convenor = identity("solo.example.com")
        with pytest.raises(PacingError):
            open_round(
                convenor,
                round_id="r-2",
                participants=[convenor.get_did()],
                schema={},
                closing_index=10,
                reveal_index=20,
                predicate=disclosure_mod.PREDICATE_MAXIMUM,
            )


# ---------------------------------------------------------------------------
# Composition: the mechanisms in one scenario
# ---------------------------------------------------------------------------


class TestPacingProfileComposition:
    def test_a_step_must_pass_every_gate_to_run(self):
        """
        One operator, one step, every gate in the profile applied in order.

        Pre-registration fixes what the step is and how it will be judged, the
        recursion ceiling bounds how far the inputs stand from a human decision,
        the oversight ratio couples compute to attested review, the red line
        policy is committed before measurement, and the pace epoch decides how
        much standing is left by the time the step is admitted.
        """
        operator_kp, operator = identity("operator.example.com")
        peer_kp, peer = identity("institute.example.org")
        human_kp, human = identity("reviewer.example.com")
        agent_kp, agent = identity("agent.example.com")
        reviewer_kp, reviewer = identity("safety.operator.example.com")

        # Red lines committed before anything is measured.
        policy = commit_policy(
            [Threshold("cyber", "cyber-uplift", ">=", 0.40, redline_mod.CONSEQUENCE_HALT)]
        )
        published_policy = publish_policy(operator, policy, log_index=10)
        assert (
            verify_open(
                open_threshold(policy, "cyber"), published_policy, operator_kp.public_key_jwk
            )
            == []
        )

        # Authorship graph: a human seeds it, an agent derives two generations.
        graph = AuthorshipGraph()
        graph.add_authorship(
            authorship_credential(
                human,
                artifact_digest="uSEED",
                author_class=recursion_mod.CLASS_HUMAN,
                custody_class=recursion_mod.CUSTODY_HUMAN_PRESENCE,
            ),
            human_kp.public_key_jwk,
        )
        for index, parent in ((1, "uSEED"), (2, "uGEN1")):
            graph.add_authorship(
                authorship_credential(
                    agent,
                    artifact_digest="uGEN%d" % index,
                    author_class=recursion_mod.CLASS_AUTONOMOUS,
                    derived_from=[parent],
                ),
                agent_kp.public_key_jwk,
            )
        step = step_credential(
            operator, step_id="run-composed", inputs=["uGEN2"], graph=graph, bound=3
        )
        assert check_step(step, operator_kp.public_key_jwk, graph) == []
        assert recursion_mod.REASON_BOUND_EXCEEDED in check_step(
            step, operator_kp.public_key_jwk, graph, bound=2
        )

        # Oversight bound against the same artifacts.
        receipt = oversight_receipt(
            reviewer,
            work_class=oversight_mod.WORK_ADVERSARIAL,
            measure=60,
            period="P1",
            artifact_digests=["uGEN2"],
            nonce="composed-1",
        )
        accumulation = accumulate(
            [receipt],
            step_artifacts=["uGEN2"],
            period="P1",
            public_keys={reviewer.get_did(): reviewer_kp.public_key_jwk},
        )
        assert check_ratio(compute_measure=1000, accumulation=accumulation, ratio=0.05) == []

        # Pre-registration and the scheduler gate.
        configuration = {"scale": "tier-3", "inputs": ["uGEN2"]}
        plan = {"evaluations": ["cyber"], "thresholds": {"cyber": 0.4}}
        registration = register_step(
            operator,
            step_id="run-composed",
            configuration=configuration,
            evaluation_plan=plan,
            min_seconds=3600,
            objection_authorities=[peer.get_did()],
            opens_at=T0,
        )
        execution = issue_execution(operator, registration=registration, log_index=20)
        assert (
            check_admission(
                execution,
                registration,
                configuration,
                operator_kp.public_key_jwk,
                now=T0 + timedelta(hours=2),
            )
            is None
        )

        # A peer objection blocks the same step.
        objection = object_to_step(peer, registration=registration, reason_code="pace")
        assert (
            check_admission(
                execution,
                registration,
                configuration,
                operator_kp.public_key_jwk,
                objections=[objection],
                objection_public_keys={peer.get_did(): peer_kp.public_key_jwk},
                now=T0 + timedelta(hours=2),
            )
            == prereg_mod.REASON_OBJECTED
        )

        # A raised pace rate contracts what the admitted step may then do.
        standing = pace_mod.effective_standing(
            anchored_at=T0,
            initial_standing=1.0,
            pace_lambda=1.0 / 1800,
            at_time=T0 + timedelta(hours=2),
        )
        assert permitted_classes(standing) == []
