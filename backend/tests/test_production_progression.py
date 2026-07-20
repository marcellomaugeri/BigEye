from __future__ import annotations

from types import SimpleNamespace


def progress(**changes):
    values = {
        "campaign_id": 9,
        "queue_files": 2,
        "executions": 100,
        "executions_per_second": 25.0,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_optional_progression_waits_for_a_healthy_basic_campaign() -> None:
    from backend.services.campaigns.production_progression import ProductionProgression

    repository_evidence = ({
        "evidence_id": "source:parser.c:8",
        "path": "parser.c",
        "excerpt": 'if (strcmp(token, "MAGIC") == 0) parse(token);',
    },)
    planner = ProductionProgression()

    recommendation = planner.next_recommendation(
        project_id=7,
        worker_count=2,
        engine="afl",
        progress=progress(executions_per_second=0.0),
        initial_complete=True,
        unhealthy=False,
        repository_evidence=repository_evidence,
        campaign_contexts={},
    )

    assert recommendation is None


def test_progression_uses_dictionary_then_cmplog_without_agent_polling() -> None:
    from backend.services.campaigns.production_progression import ProductionProgression

    repository_evidence = ({
        "evidence_id": "source:parser.c:8",
        "path": "parser.c",
        "excerpt": 'if (strcmp(token, "MAGIC") == 0) parse(token);',
    },)
    planner = ProductionProgression()
    first = planner.next_recommendation(
        project_id=7, worker_count=2, engine="afl", progress=progress(),
        initial_complete=True, unhealthy=False,
        repository_evidence=repository_evidence, campaign_contexts={},
    )
    second = planner.next_recommendation(
        project_id=7, worker_count=2, engine="afl", progress=progress(),
        initial_complete=True, unhealthy=False,
        repository_evidence=repository_evidence,
        campaign_contexts={10: {"configuration_purpose": "enable dictionary"}},
    )

    assert first.action.name == "enable dictionary"
    assert second.action.name == "enable CmpLog"
    assert first.supporting_evidence_ids == ("source:parser.c:8",)
    assert not hasattr(planner, "manager")


def test_progression_uses_one_documented_configuration_candidate() -> None:
    from backend.services.campaigns.production_progression import ProductionProgression

    recommendation = ProductionProgression().next_recommendation(
        project_id=7, worker_count=2, engine="afl", progress=progress(),
        initial_complete=True, unhealthy=False,
        repository_evidence=({
            "evidence_id": "docs:README.md:42", "path": "README.md",
            "excerpt": "Use --encrypt to enable encrypted protocol mode.",
        },),
        campaign_contexts={},
    )

    assert recommendation.action.name == "try configuration"
    assert recommendation.action.arguments == ("--encrypt",)
    assert recommendation.action.detail == "--encrypt"


def test_progression_gates_component_gap_special_sanitizer_and_pinned_json_grammar() -> None:
    from backend.services.campaigns.production_progression import ProductionProgression

    planner = ProductionProgression()
    cases = (
        (({
            "evidence_id": "gap:decoder", "kind": "system_coverage_gap",
            "provenance": "clean_coverage", "source_path": "decoder.c",
        },), "prepare component gap target"),
        (({
            "evidence_id": "source:worker.cc:7", "path": "worker.cc",
            "excerpt": "std::thread worker(run);",
        },), "run specialised sanitizer replay"),
        (({
            "evidence_id": "source:json.c:4", "path": "json.c",
            "excerpt": "json_parse(input, size);",
        },), "enable grammar mutator"),
    )

    for repository_evidence, expected in cases:
        recommendation = planner.next_recommendation(
            project_id=7, worker_count=2, engine="afl", progress=progress(),
            initial_complete=True, unhealthy=False,
            repository_evidence=repository_evidence, campaign_contexts={},
        )
        assert recommendation.action.name == expected

    grammar = planner.next_recommendation(
        project_id=7, worker_count=2, engine="afl", progress=progress(),
        initial_complete=True, unhealthy=False,
        repository_evidence=cases[-1][0], campaign_contexts={},
    )
    assert grammar.action.environment == ((
        "AFL_CUSTOM_MUTATOR_LIBRARY",
        "/usr/local/lib/afl/libgrammarmutator-json.so",
    ),)


def test_libfuzzer_never_receives_afl_only_or_untyped_cli_progressions() -> None:
    from backend.services.campaigns.production_progression import ProductionProgression

    recommendation = ProductionProgression().next_recommendation(
        project_id=7, worker_count=2, engine="libfuzzer", progress=progress(),
        initial_complete=True, unhealthy=False,
        repository_evidence=(
            {
                "evidence_id": "source:json.c:4", "path": "json.c",
                "excerpt": "json_parse(input, size);",
            },
            {
                "evidence_id": "docs:README.md:42", "path": "README.md",
                "excerpt": "Use --encrypt to enable encrypted protocol mode.",
            },
        ),
        campaign_contexts={},
    )

    assert recommendation is None
