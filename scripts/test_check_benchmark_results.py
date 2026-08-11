#!/usr/bin/env python3
"""Self-test for check_benchmark_results.py.

The parser is the only thing standing between "the benchmark printed something"
and "the benchmark proved something", so its refusals are the behaviour worth
pinning. Each case below is one way a run can look green while having proved
nothing: a truncated suite, a spliced capture, a record that contradicts itself,
a required gate that vanished, a timing threshold enforced on the wrong host.

Run standalone; exits 0 when every case behaves.
"""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_benchmark_results as checker

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
        self.assertEqual(metrics["scanner.verify_gib_per_s"].value, 9.5)
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
        self.refuses(CLEAN.replace("#METRIC\tscanner", "#METRIC\tforeign"), "no preceding gate")

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

    def test_status_must_agree_with_its_own_numbers(self):
        lying = CLEAN.replace(
            "scanner.prefilter_dmk_over_libc\ttiming\tpass\t1.400000\t>=\t1.000000",
            "scanner.prefilter_dmk_over_libc\ttiming\tpass\t0.400000\t>=\t1.000000",
        )
        self.refuses(lying, "reports pass but")


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
    unittest.main(verbosity=2)
