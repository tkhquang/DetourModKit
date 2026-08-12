#!/usr/bin/env python3
"""Self-test for check_benchmark_results.py.

The parser is the only thing standing between "the benchmark printed something"
and "the benchmark proved something", so its refusals are the behaviour worth
pinning. Each case below is one way a run can look green while having proved
nothing: a truncated suite, a spliced capture, a record that contradicts itself,
a required gate that vanished, a timing threshold enforced on the wrong host.

Run standalone; exits 0 when every case behaves.
"""
import argparse
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_benchmark_results as checker

LEDGER_PROBE = None


def resolve_probe(path):
    """Return an absolute, existing path for the compiled ledger probe.

    Windows `CreateProcess` refuses a relative program path spelled with forward slashes and no leading `./`, which
    is exactly what `find build/mingw-release -name dmk_bench_gate_probe.exe` hands the release workflow. Resolving
    here rather than at each call site keeps every caller -- CTest's generator expression, the workflow's find, an
    operator's shell -- on the same spelling, and turns a wrong path into one diagnostic instead of an exec traceback.
    """
    resolved = os.path.abspath(path)
    if not os.path.isfile(resolved):
        raise SystemExit("--ledger-probe '{0}' is not a file; build dmk_bench_gate_probe first.".format(path))
    return resolved


CLEAN = "\n".join(
    [
        "DetourModKit Scanner microbenchmark",
        "#GATE\tscanner\tscanner.scenario_anchor_agreement\tdeterministic\tpass\t1.000000\t>=\t1.000000",
        "#GATE\tscanner\tscanner.prefilter_dmk_over_libc\ttiming\tpass\t1.400000\t>=\t1.000000",
        "#METRIC\tscanner\tscanner.verify_gib_per_s\t9.500000",
        "#HOST\tstable-host-a",
        "#BUILD\tAVX2",
        "#TIER\tAVX2",
        "#GATE-END\tscanner\t2",
        "",
    ]
)

RATIO_OPTIONS = [
    "--current-tier",
    "AVX-512",
    "--baseline-tier",
    "AVX2",
    "--current-build",
    "AVX512",
    "--baseline-build",
    "AVX2",
]


def current_capture(text=CLEAN):
    return text.replace("#BUILD\tAVX2", "#BUILD\tAVX512").replace("#TIER\tAVX2", "#TIER\tAVX-512")


def ratio_command(current, baseline, stable=False):
    command = [
        current,
        "--baseline",
        baseline,
        "--metric-ratio",
        "scanner.verify_gib_per_s:1.30",
        *RATIO_OPTIONS,
    ]
    if stable:
        command.append("--stable-host")
    return command


def write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


class ParserRefusals(unittest.TestCase):
    def refuses(self, text, fragment):
        with self.assertRaises(checker.RecordError) as caught:
            checker.parse_records(text, "sample")
        self.assertIn(fragment, str(caught.exception))

    def test_clean_capture_parses(self):
        gates, metrics, provenance = checker.parse_records(CLEAN, "sample")
        self.assertEqual([gate.name for gate in gates], [
            "scanner.scenario_anchor_agreement",
            "scanner.prefilter_dmk_over_libc",
        ])
        self.assertEqual(metrics[("scanner", "scanner.verify_gib_per_s")].value, 9.5)
        self.assertNotIn("scanner.verify_gib_per_s", metrics)
        self.assertEqual(provenance, {"host": "stable-host-a", "build": "AVX2", "tier": "AVX2"})

    def test_no_records_is_no_evidence(self):
        self.refuses("just a human table\nwith no records\n", "no gate records")

    def test_missing_sentinel_is_a_truncated_run(self):
        truncated = "\n".join(line for line in CLEAN.splitlines() if not line.startswith("#GATE-END"))
        self.refuses(truncated, "no #GATE-END")

    def test_sentinel_count_must_match_the_records(self):
        self.refuses(CLEAN.replace("#GATE-END\tscanner\t2", "#GATE-END\tscanner\t3"), "declares 3 gates but 2")

    def test_gate_after_the_sentinel_is_a_spliced_capture(self):
        spliced = CLEAN + "#GATE\tscanner\tscanner.late\tdeterministic\tpass\t1.000000\t>=\t1.000000\n"
        self.refuses(spliced, "follows suite 'scanner' sentinel")

    def test_metric_after_the_sentinel_is_a_spliced_capture(self):
        metric = "#METRIC\tscanner\tscanner.verify_gib_per_s\t9.500000\n"
        spliced = CLEAN.replace(metric, "") + metric
        self.refuses(spliced, "follows suite 'scanner' sentinel")

    def test_metric_from_an_unclosed_suite_is_refused(self):
        # Qualified consistently with its own suite, so this reaches the no-preceding-gate rule rather than the
        # identity rule above it.
        self.refuses(
            CLEAN.replace("#METRIC\tscanner\tscanner.verify_gib_per_s", "#METRIC\tforeign\tforeign.verify_gib_per_s"),
            "no preceding gate",
        )

    def test_provenance_after_the_sentinel_is_a_spliced_capture(self):
        # Provenance describes the run that produced the records above it. Trailing it after the sentinel means it
        # describes a different run, which is exactly what the stable-host comparison must never accept.
        self.refuses(CLEAN + "#TIER\tAVX-512\n", "provenance follows a terminal suite sentinel")

    def test_duplicate_provenance_is_refused(self):
        self.refuses(CLEAN.replace("#TIER\tAVX2\n", "#TIER\tAVX2\n#TIER\tAVX-512\n"), "duplicate tier provenance")

    def test_empty_provenance_is_refused(self):
        self.refuses(CLEAN.replace("#HOST\tstable-host-a", "#HOST\t"), "host provenance is empty")

    def test_duplicate_gate_name_is_refused(self):
        doubled = CLEAN.replace(
            "#GATE-END",
            "#GATE\tscanner\tscanner.scenario_anchor_agreement\tdeterministic\tpass\t1.000000\t>=\t1.000000\n#GATE-END",
        )
        self.refuses(doubled, "duplicate gate name")

    def test_short_record_is_malformed(self):
        self.refuses(CLEAN.replace("\tdeterministic\tpass\t1.000000\t>=\t1.000000", "\tpass"), "expected 8")

    def test_unknown_kind_is_malformed(self):
        self.refuses(CLEAN.replace("\tdeterministic\t", "\tadvisory\t"), "unknown gate kind")

    def test_unparsable_number_is_malformed(self):
        self.refuses(CLEAN.replace("\t1.400000\t>=", "\tfast\t>="), "observed 'fast' is not a number")

    def test_nonfinite_gate_number_is_malformed(self):
        self.refuses(CLEAN.replace("\t1.400000\t>=", "\tnan\t>="), "is not finite")

    def test_nonfinite_metric_is_malformed(self):
        self.refuses(CLEAN.replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\tinf"), "is not finite")

    def test_an_empty_suite_is_refused(self):
        self.refuses(CLEAN.replace("#GATE\tscanner\tscanner.scenario", "#GATE\t\tscanner.scenario"), "empty suite")

    def test_an_empty_sentinel_suite_is_refused(self):
        self.refuses(CLEAN.replace("#GATE-END\tscanner\t2", "#GATE-END\t\t2"), "sentinel has an empty suite")

    def test_a_dotted_gate_suite_is_refused(self):
        self.refuses(
            CLEAN.replace(
                "#GATE\tscanner\tscanner.scenario_anchor_agreement",
                "#GATE\tscanner.verify\tscanner.verify.scenario_anchor_agreement",
            ),
            "contains '.'",
        )

    def test_a_dotted_metric_suite_is_refused(self):
        self.refuses(
            CLEAN.replace(
                "#METRIC\tscanner\tscanner.verify_gib_per_s",
                "#METRIC\tscanner.verify\tscanner.verify.gib_per_s",
            ),
            "contains '.'",
        )

    def test_a_dotted_sentinel_suite_is_refused(self):
        self.refuses(CLEAN.replace("#GATE-END\tscanner\t2", "#GATE-END\tscanner.verify\t2"), "contains '.'")

    def test_an_empty_name_is_refused(self):
        self.refuses(CLEAN.replace("\tscanner.scenario_anchor_agreement\t", "\t\t"), "has an empty name")

    def test_an_unqualified_name_is_refused(self):
        self.refuses(
            CLEAN.replace("scanner.scenario_anchor_agreement", "scenario_anchor_agreement"),
            "is not qualified with its suite",
        )

    def test_a_bare_suite_prefix_with_no_remainder_is_refused(self):
        self.refuses(CLEAN.replace("scanner.scenario_anchor_agreement", "scanner."), "is not qualified with its suite")

    def test_a_name_qualified_with_a_foreign_suite_is_refused(self):
        # The exact false-green this binding exists for: a foreign suite emitting a record under the scanner's prefix.
        self.refuses(
            CLEAN.replace("#GATE\tscanner\tscanner.scenario", "#GATE\tmemory\tscanner.scenario"),
            "is not qualified with its suite",
        )

    def test_an_empty_metric_identity_is_refused(self):
        self.refuses(CLEAN.replace("#METRIC\tscanner\tscanner.verify_gib_per_s", "#METRIC\tscanner\t"), "empty name")

    def test_a_duplicate_metric_tuple_is_refused(self):
        metric = "#METRIC\tscanner\tscanner.verify_gib_per_s\t9.500000"
        self.refuses(CLEAN.replace(metric, metric + "\n" + metric), "duplicate metric name")

    def test_status_must_agree_with_its_own_numbers(self):
        lying = CLEAN.replace(
            "scanner.prefilter_dmk_over_libc\ttiming\tpass\t1.400000\t>=\t1.000000",
            "scanner.prefilter_dmk_over_libc\ttiming\tpass\t0.400000\t>=\t1.000000",
        )
        self.refuses(lying, "reports pass but")


class ProducerBoundary(unittest.TestCase):
    CONTROL = "#GATE\tscanner\tscanner.control\tdeterministic\tpass\t1.000000\t>=\t1.000000"
    SENTINEL = "#GATE-END\tscanner\t1"

    def run_probe(self, mode):
        self.assertIsNotNone(LEDGER_PROBE, "--ledger-probe is required")
        return subprocess.run([LEDGER_PROBE, mode], text=True, capture_output=True)

    def test_valid_gate_metric_and_count_close_cleanly(self):
        result = self.run_probe("valid")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                self.CONTROL,
                "#METRIC\tscanner\tscanner.value\t2.000000",
                self.SENTINEL,
            ],
        )
        self.assertEqual(result.stderr, "")

    def test_invalid_suites_fail_before_emitting_evidence(self):
        for mode in ("null_suite", "empty_suite", "dotted_suite"):
            with self.subTest(mode=mode):
                result = self.run_probe(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("refusing suite", result.stderr)
                self.assertIn("must be nonempty and contain no '.'", result.stderr)

    def test_zero_gate_and_metric_only_ledgers_fail_closed(self):
        zero = self.run_probe("zero_records")
        self.assertNotEqual(zero.returncode, 0)
        self.assertEqual(zero.stdout.splitlines(), ["#GATE-END\tscanner\t0"])
        self.assertIn("must emit at least one gate", zero.stderr)

        metric = self.run_probe("metric_only")
        self.assertNotEqual(metric.returncode, 0)
        self.assertEqual(
            metric.stdout.splitlines(),
            ["#METRIC\tscanner\tscanner.value\t2.000000", "#GATE-END\tscanner\t0"],
        )
        self.assertIn("must emit at least one gate", metric.stderr)

    def test_invalid_gate_and_metric_names_are_not_emitted_and_make_close_fail(self):
        modes = (
            "null_gate",
            "empty_gate",
            "unqualified_gate",
            "bare_gate",
            "foreign_gate",
            "null_metric",
            "empty_metric",
            "unqualified_metric",
            "bare_metric",
            "foreign_metric",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                result = self.run_probe(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.splitlines(), [self.CONTROL, self.SENTINEL])
                self.assertIn("refusing record", result.stderr)

    def test_deterministic_and_timing_failures_keep_distinct_exit_policy(self):
        deterministic = self.run_probe("deterministic_fail")
        self.assertNotEqual(deterministic.returncode, 0)
        self.assertEqual(
            deterministic.stdout.splitlines(),
            [
                "#GATE\tscanner\tscanner.control\tdeterministic\tfail\t0.000000\t>=\t1.000000",
                self.SENTINEL,
            ],
        )

        timing = self.run_probe("timing_fail")
        self.assertEqual(timing.returncode, 0, timing.stderr)
        self.assertEqual(
            timing.stdout.splitlines(),
            [
                "#GATE\tscanner\tscanner.control\ttiming\tfail\t0.500000\t>=\t1.000000",
                self.SENTINEL,
            ],
        )

    def test_a_relative_forward_slash_probe_path_still_executes(self):
        """`find build/... -name dmk_bench_gate_probe.exe` prints exactly this spelling, and Windows refuses it raw.

        The directory the spelling is taken from is the probe's own grandparent rather than the caller's, so the
        shape under test is always a directory-qualified relative path and never a bare name a CreateProcess search
        would resolve out of the working directory anyway.
        """
        self.assertIsNotNone(LEDGER_PROBE, "--ledger-probe is required")
        anchor = os.path.dirname(os.path.dirname(LEDGER_PROBE))
        relative = os.path.relpath(LEDGER_PROBE, anchor).replace(os.sep, "/")
        self.assertIn("/", relative)
        previous = os.getcwd()
        os.chdir(anchor)
        try:
            result = subprocess.run([resolve_probe(relative), "valid"], text=True, capture_output=True)
        finally:
            os.chdir(previous)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], self.SENTINEL)

    def test_close_is_terminal_and_emits_exactly_one_sentinel(self):
        for mode in ("double_close", "gate_after_close", "metric_after_close"):
            with self.subTest(mode=mode):
                result = self.run_probe(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.splitlines(), [self.CONTROL, self.SENTINEL])
                self.assertIn("already closed", result.stderr)


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="dmk_bench_gate_")

    def test_clean_run_passes(self):
        path = write(self.directory, "clean.txt", CLEAN)
        self.assertEqual(checker.main([path]), 0)

    def test_actual_cli_propagates_success_and_refusal_exit_codes(self):
        clean = write(self.directory, "clean-cli.txt", CLEAN)
        truncated = write(
            self.directory,
            "truncated-cli.txt",
            "\n".join(line for line in CLEAN.splitlines() if not line.startswith("#GATE-END")),
        )
        self.assertEqual(subprocess.run([sys.executable, checker.__file__, clean], capture_output=True).returncode, 0)
        self.assertNotEqual(
            subprocess.run([sys.executable, checker.__file__, truncated], capture_output=True).returncode,
            0,
        )

    def test_actual_cli_rejects_a_nonfinite_ratio_floor(self):
        current = write(self.directory, "current-cli.txt", current_capture())
        baseline = write(self.directory, "baseline-cli.txt", CLEAN)
        command = ratio_command(current, baseline, stable=True)
        command[command.index("scanner.verify_gib_per_s:1.30")] = "scanner.verify_gib_per_s:inf"
        self.assertNotEqual(subprocess.run([sys.executable, checker.__file__, *command], capture_output=True).returncode, 0)

    def test_missing_file_fails(self):
        self.assertEqual(checker.main([os.path.join(self.directory, "absent.txt")]), 1)

    def test_failed_deterministic_gate_fails_anywhere(self):
        broken = CLEAN.replace(
            "scanner.scenario_anchor_agreement\tdeterministic\tpass\t1.000000\t>=\t1.000000",
            "scanner.scenario_anchor_agreement\tdeterministic\tfail\t0.000000\t>=\t1.000000",
        )
        path = write(self.directory, "broken.txt", broken)
        self.assertEqual(checker.main([path]), 1)

    def test_failed_timing_gate_needs_a_stable_host(self):
        slow = CLEAN.replace(
            "scanner.prefilter_dmk_over_libc\ttiming\tpass\t1.400000\t>=\t1.000000",
            "scanner.prefilter_dmk_over_libc\ttiming\tfail\t0.800000\t>=\t1.000000",
        )
        path = write(self.directory, "slow.txt", slow)
        self.assertEqual(checker.main([path]), 0)
        self.assertEqual(checker.main([path, "--stable-host"]), 1)

    def test_required_gate_must_be_present(self):
        path = write(self.directory, "clean.txt", CLEAN)
        self.assertEqual(checker.main([path, "--require", "scanner.scenario_anchor_agreement"]), 0)
        self.assertEqual(checker.main([path, "--require", "scanner.gate_that_was_deleted"]), 1)

    def test_a_timing_gate_cannot_satisfy_a_required_correctness_identity(self):
        timing = CLEAN.replace(
            "scanner.scenario_anchor_agreement\tdeterministic",
            "scanner.scenario_anchor_agreement\ttiming",
        )
        path = write(self.directory, "timing-required.txt", timing)
        self.assertEqual(checker.main([path, "--require", "scanner.scenario_anchor_agreement"]), 1)

    def test_a_required_name_is_bound_to_its_own_suite(self):
        # A suite that renamed itself still emits the requested name; only the exact tuple catches that.
        moved = CLEAN.replace("\tscanner\t", "\tmemory\t").replace(
            "scanner.scenario_anchor_agreement", "memory.scenario_anchor_agreement"
        ).replace("scanner.prefilter_dmk_over_libc", "memory.prefilter_dmk_over_libc").replace(
            "scanner.verify_gib_per_s", "memory.verify_gib_per_s"
        ).replace("#GATE-END\tscanner", "#GATE-END\tmemory")
        path = write(self.directory, "moved.txt", moved)
        self.assertEqual(checker.main([path]), 0)
        self.assertEqual(checker.main([path, "--require", "memory.scenario_anchor_agreement"]), 0)
        self.assertEqual(checker.main([path, "--require", "scanner.scenario_anchor_agreement"]), 1)

    def test_a_requirement_binds_the_exact_suite_and_name_pair(self):
        # Driven below the parser on purpose: the identity rule already refuses a foreign-qualified record, so this is
        # the only place the pair binding itself can be observed rather than inferred from that rule holding.
        foreign = checker.Gate("memory", "scanner.scenario_anchor_agreement", "deterministic", "pass", 1.0, ">=", 1.0)
        self.assertEqual(
            checker.unmet_requirements([foreign], [("scanner", "scanner.scenario_anchor_agreement")]),
            [("scanner", "scanner.scenario_anchor_agreement")],
        )
        self.assertEqual(
            checker.unmet_requirements([foreign], [("memory", "scanner.scenario_anchor_agreement")]), []
        )

    def test_an_unqualified_requirement_is_rejected_at_the_command_line(self):
        path = write(self.directory, "clean.txt", CLEAN)
        for requirement in ("scenario_anchor_agreement", ".scenario_anchor_agreement", "scanner."):
            with self.subTest(requirement=requirement):
                with self.assertRaises(SystemExit) as caught:
                    checker.main([path, "--require", requirement])
                self.assertNotEqual(caught.exception.code, 0)

    def test_a_metric_ratio_binds_the_exact_suite_and_name_pair_below_the_parser(self):
        name = "scanner.verify_gib_per_s"
        current_gates = [
            checker.Gate("memory", "memory.scenario", "deterministic", "pass", 1.0, ">=", 1.0)
        ]
        baseline_gates = [
            checker.Gate("memory", "memory.scenario", "deterministic", "pass", 1.0, ">=", 1.0)
        ]
        # Indexed under the REQUESTED identity while the record still declares suite "memory", so the lookup succeeds
        # and execution reaches the mismatch guard. Keying it under ("memory", name) would stop at the missing-metric
        # branch above and never exercise the guard this case exists for. The values would also fail the 1.30 floor,
        # so a guard that only warned and fell through would additionally report a ratio between the two metrics it
        # just refused; requiring that report to be ABSENT is what pins the refusal as terminal.
        responses = [
            (
                current_gates,
                {("scanner", name): checker.Metric("memory", name, 10.0)},
                {"host": "stable-host-a", "build": "AVX512", "tier": "AVX-512"},
            ),
            (
                baseline_gates,
                {("scanner", name): checker.Metric("memory", name, 14.0)},
                {"host": "stable-host-a", "build": "AVX2", "tier": "AVX2"},
            ),
        ]
        captured = io.StringIO()
        with mock.patch.object(checker, "read_result", side_effect=responses):
            with contextlib.redirect_stdout(captured):
                verdict = checker.main(ratio_command("current.txt", "baseline.txt", stable=True))
        output = captured.getvalue()
        self.assertEqual(verdict, 1, output)
        self.assertIn("but belongs to current suite 'memory'", output)
        self.assertNotIn("ratio", output)

    def test_metric_ratio_parser_preserves_the_suite_and_full_name(self):
        self.assertEqual(
            checker.parse_metric_ratio("scanner.verify_gib_per_s:1.30"),
            ("scanner", "scanner.verify_gib_per_s", 1.3),
        )

    def test_same_suite_cannot_be_spliced_across_files(self):
        first = write(self.directory, "first.txt", CLEAN)
        second = write(self.directory, "second.txt", CLEAN)
        self.assertEqual(checker.main([first, second]), 1)

    def test_metric_ratio_needs_a_baseline_and_a_stable_host(self):
        current = write(self.directory, "current.txt", current_capture())
        baseline = write(
            self.directory,
            "baseline.txt",
            CLEAN.replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000"),
        )
        self.assertEqual(checker.main([current, "--metric-ratio", "scanner.verify_gib_per_s:1.30", *RATIO_OPTIONS]), 1)
        self.assertEqual(checker.main(ratio_command(current, baseline)), 0)
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_metric_ratio_clears_its_floor_on_a_stable_host(self):
        current = write(
            self.directory,
            "fast.txt",
            current_capture(CLEAN).replace(
                "scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000"
            ),
        )
        baseline = write(
            self.directory,
            "slow.txt",
            CLEAN.replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000"),
        )
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 0)

    def test_failed_baseline_deterministic_gate_cannot_certify_a_ratio(self):
        current = write(
            self.directory,
            "current.txt",
            current_capture().replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000"),
        )
        baseline_text = CLEAN.replace(
            "scanner.scenario_anchor_agreement\tdeterministic\tpass\t1.000000\t>=\t1.000000",
            "scanner.scenario_anchor_agreement\tdeterministic\tfail\t0.000000\t>=\t1.000000",
        ).replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000")
        baseline = write(self.directory, "failed-baseline.txt", baseline_text)
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_ratio_requires_declared_tiers_and_build_roles(self):
        baseline = write(self.directory, "baseline.txt", CLEAN)
        fast = current_capture().replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000")
        for label, broken in (
            ("missing-tier", fast.replace("#TIER\tAVX-512\n", "")),
            ("same-tier", fast.replace("#TIER\tAVX-512", "#TIER\tAVX2")),
            ("wrong-build", fast.replace("#BUILD\tAVX512", "#BUILD\tAVX2")),
        ):
            with self.subTest(label=label):
                current = write(self.directory, label + ".txt", broken)
                self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_reversed_tiers_are_refused(self):
        current = write(
            self.directory,
            "reversed-current.txt",
            CLEAN.replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000"),
        )
        baseline = write(
            self.directory,
            "reversed-baseline.txt",
            current_capture(CLEAN).replace(
                "scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000"
            ),
        )
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_ratio_requires_the_same_identified_host(self):
        current = write(
            self.directory,
            "current.txt",
            current_capture().replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000"),
        )
        baseline = write(
            self.directory,
            "other-host.txt",
            CLEAN.replace("#HOST\tstable-host-a", "#HOST\tstable-host-b").replace(
                "scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000"
            ),
        )
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_ratio_requires_matching_deterministic_scenarios(self):
        current = write(
            self.directory,
            "current.txt",
            current_capture().replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t14.000000"),
        )
        baseline = write(
            self.directory,
            "different-scenario.txt",
            CLEAN.replace("scanner.scenario_anchor_agreement", "scanner.other_setup").replace(
                "scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t10.000000"
            ),
        )
        self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)

    def test_ratio_operands_must_be_positive(self):
        for label, current_value, baseline_value in (("zero-current", "0", "10"), ("negative-baseline", "14", "-10")):
            with self.subTest(label=label):
                current = write(
                    self.directory,
                    label + "-current.txt",
                    current_capture().replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t" + current_value),
                )
                baseline = write(
                    self.directory,
                    label + "-baseline.txt",
                    CLEAN.replace("scanner.verify_gib_per_s\t9.500000", "scanner.verify_gib_per_s\t" + baseline_value),
                )
                self.assertEqual(checker.main(ratio_command(current, baseline, stable=True)), 1)


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(add_help=False)
    argument_parser.add_argument("--ledger-probe", required=True)
    arguments, unittest_arguments = argument_parser.parse_known_args()
    LEDGER_PROBE = resolve_probe(arguments.ledger_probe)
    unittest.main(argv=[sys.argv[0], *unittest_arguments], verbosity=2)
