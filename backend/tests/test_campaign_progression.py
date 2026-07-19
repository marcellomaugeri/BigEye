from __future__ import annotations


def test_configuration_planner_returns_one_documented_evidence_backed_candidate() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationEvidence, ConfigurationHypothesis, ConfigurationPlanner

    evidence = ConfigurationEvidence((
        ConfigurationHypothesis("enable encryption", ("--encrypt",), (), ("README.md:42",), documented=True),
        ConfigurationHypothesis("enable auxiliary protocol", ("--aux",), (), ("docs/protocol.md:8",), documented=True),
    ))

    candidate = ConfigurationPlanner.next_candidate(evidence, tried=())

    assert candidate is not None
    assert candidate.name == "enable encryption"
    assert candidate.evidence_ids == ("README.md:42",)
    assert candidate.arguments == ("--encrypt",)


def test_configuration_planner_skips_undocumented_or_tried_hypotheses_without_combining_them() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationEvidence, ConfigurationHypothesis, ConfigurationPlanner

    evidence = ConfigurationEvidence((
        ConfigurationHypothesis("guess", ("--guess",), (), (), documented=False),
        ConfigurationHypothesis("first", ("--first",), (), ("docs:1",), documented=True),
        ConfigurationHypothesis("second", ("--second",), (), ("docs:2",), documented=True),
    ))

    candidate = ConfigurationPlanner.next_candidate(evidence, tried=("first",))

    assert candidate is not None
    assert candidate.name == "second"
    assert candidate.arguments == ("--second",)
    assert "--first" not in candidate.arguments


def test_configuration_planner_rejects_blank_evidence_identifiers() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationEvidence, ConfigurationHypothesis, ConfigurationPlanner

    evidence = ConfigurationEvidence((
        ConfigurationHypothesis("unsupported", ("--guess",), (), ("",), documented=True),
    ))

    assert ConfigurationPlanner.next_candidate(evidence, tried=()) is None


def test_configuration_is_retained_only_for_unique_clean_evidence_or_distinct_crash() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationOutcome, ConfigurationPlanner

    redundant = ConfigurationPlanner.evaluate(ConfigurationOutcome())
    useful = ConfigurationPlanner.evaluate(ConfigurationOutcome(unique_clean_lines=frozenset({"a.c:2"})))
    crash = ConfigurationPlanner.evaluate(ConfigurationOutcome(distinct_crash=True))

    assert redundant.retained is False
    assert useful.retained is True
    assert crash.retained is True


def test_sanitizer_planner_starts_with_address_and_undefined_without_enabling_every_sanitizer() -> None:
    from backend.fuzzing.campaigns.sanitizers import SanitizerPlanner, SanitizerTarget

    plan = SanitizerPlanner.plan(SanitizerTarget(concurrent=False), worker_count=2)

    assert plan.primary == ("address", "undefined")
    assert "thread" not in plan.replay_variants
    assert "leak" not in plan.replay_variants
    assert plan.quality_signals == ("leak",)


def test_special_sanitizers_require_their_exact_target_evidence_and_run_as_separate_variants() -> None:
    from backend.fuzzing.campaigns.sanitizers import SanitizerPlanner, SanitizerTarget

    target = SanitizerTarget(
        concurrent=True,
        fully_instrumentable_dependency_closure=True,
        language="c++",
        lto_compatible=True,
    )
    plan = SanitizerPlanner.plan(target, worker_count=4)

    assert plan.replay_variants == ("memory", "thread", "cfi")
    assert all(variant not in plan.primary for variant in plan.replay_variants)
    assert plan.leak_classification == "quality evidence"


def test_progression_starts_with_build_sanitizer_seed_health_and_basic_fuzzer_in_order() -> None:
    from backend.fuzzing.campaigns.progression import CampaignProgression, ProgressionEvidence

    first = CampaignProgression.next_step(ProgressionEvidence())
    second = CampaignProgression.next_step(ProgressionEvidence(normal_build_ready=True))
    third = CampaignProgression.next_step(ProgressionEvidence(normal_build_ready=True, baseline_sanitizers_validated=True))
    fourth = CampaignProgression.next_step(ProgressionEvidence(
        normal_build_ready=True,
        baseline_sanitizers_validated=True,
        seed_coverage_healthy=True,
    ))

    assert [first.name, second.name, third.name, fourth.name] == [
        "prepare normal build",
        "validate address and undefined",
        "validate seed and coverage health",
        "start basic fuzzer",
    ]


def test_grammar_never_precedes_a_healthy_basic_campaign_and_keeps_native_mutations() -> None:
    from backend.fuzzing.campaigns.progression import CampaignProgression, ProgressionEvidence

    unhealthy = ProgressionEvidence(
        normal_build_ready=True,
        baseline_sanitizers_validated=True,
        seed_coverage_healthy=True,
        basic_fuzzer_running=True,
        basic_campaign_healthy=False,
        grammar_library="/opt/bigeye/mutators/libgrammar.so",
        grammar_evidence_ids=("grammar.json:1",),
    )
    healthy = ProgressionEvidence(**{**unhealthy.__dict__, "basic_campaign_healthy": True})

    assert CampaignProgression.next_step(unhealthy) is None
    action = CampaignProgression.next_step(healthy)
    assert action is not None
    assert action.name == "enable grammar mutator"
    assert action.environment == (("AFL_CUSTOM_MUTATOR_LIBRARY", "/opt/bigeye/mutators/libgrammar.so"),)
    assert all(name != "AFL_CUSTOM_MUTATOR_ONLY" for name, _value in action.environment)


def test_afl_only_progressions_are_not_offered_to_libfuzzer_campaigns() -> None:
    from backend.fuzzing.campaigns.progression import CampaignProgression, ProgressionEvidence

    evidence = ProgressionEvidence(
        engine="libfuzzer",
        normal_build_ready=True,
        baseline_sanitizers_validated=True,
        seed_coverage_healthy=True,
        basic_fuzzer_running=True,
        basic_campaign_healthy=True,
        cmplog_evidence_ids=("comparison:a.c:1",),
        grammar_library="/opt/bigeye/mutator.so",
        grammar_evidence_ids=("grammar:1",),
    )

    assert CampaignProgression.next_step(evidence) is None


def test_each_configuration_progression_has_a_distinct_completion_key() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationCandidate
    from backend.fuzzing.campaigns.progression import CampaignProgression, ProgressionEvidence

    common = dict(
        normal_build_ready=True,
        baseline_sanitizers_validated=True,
        seed_coverage_healthy=True,
        basic_fuzzer_running=True,
        basic_campaign_healthy=True,
    )
    first = CampaignProgression.next_step(ProgressionEvidence(
        **common,
        configuration=ConfigurationCandidate("encrypted", ("--encrypt",), (), ("docs:1",)),
    ))
    second = CampaignProgression.next_step(ProgressionEvidence(
        **common,
        configuration=ConfigurationCandidate("auxiliary", ("--aux",), (), ("docs:2",)),
        completed_actions=(first.key,),
    ))

    assert first.key == "try configuration:encrypted"
    assert second is not None
    assert second.key == "try configuration:auxiliary"


def test_optional_progression_uses_one_evidence_backed_improvement_at_a_time() -> None:
    from backend.fuzzing.campaigns.configuration import ConfigurationCandidate
    from backend.fuzzing.campaigns.progression import CampaignProgression, ProgressionEvidence

    base = dict(
        normal_build_ready=True,
        baseline_sanitizers_validated=True,
        seed_coverage_healthy=True,
        basic_fuzzer_running=True,
        basic_campaign_healthy=True,
    )
    evidence = ProgressionEvidence(
        **base,
        dictionary_evidence_ids=("strings:parser.c:8",),
        cmplog_evidence_ids=("comparison:parser.c:12",),
        configuration=ConfigurationCandidate("encrypted mode", ("--encrypt",), (), ("README.md:42",)),
    )

    first = CampaignProgression.next_step(evidence)
    second = CampaignProgression.next_step(ProgressionEvidence(**{**evidence.__dict__, "completed_actions": (first.name,)}))

    assert first.name == "enable dictionary"
    assert second.name == "enable CmpLog"
    assert len(first.evidence_ids) == 1
    assert len(second.evidence_ids) == 1
