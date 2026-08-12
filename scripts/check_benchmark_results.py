#!/usr/bin/env python3
"""Gate a benchmark run's recorded evidence, failing closed on anything it cannot read.

The benchmark executables under ``tests/`` emit the record set defined in
``tests/bench_gate.hpp``. This checker is the half that decides whether a run
counts as evidence:

  ``#GATE``      suite, name, kind, status, observed, relation, threshold
  ``#METRIC``    suite, name, value
  ``#GATE-END``  suite, number of gate records that suite emitted
  ``#TIER``      selected SIMD tier
  ``#BUILD``     intrinsic build role
  ``#HOST``      operator-supplied stable-host identity

Everything below is a refusal, because each one is a way a benchmark can look
green without having proved anything:

  - a result file that is missing, unreadable, or has no records at all
  - a record that does not match its grammar, is non-finite, or repeats evidence
  - a record with an empty or dotted suite, an empty name, or a name not qualified
    with its own suite: an identity no suite owns is one a ``--require`` cannot
    bind to, and a foreign suite's prefix lets one suite answer for another
  - a suite with no ``#GATE-END``, or whose sentinel count disagrees with the
    records seen (a run killed mid-suite, or output spliced from two runs)
  - a record whose ``status`` disagrees with its own observed/threshold pair
  - a failed deterministic gate
  - a ``--require``d deterministic gate identity that its suite did not emit

Deterministic gates are correctness facts and block on any host. Timing gates
and ``--metric-ratio`` comparisons describe wall-clock behaviour, so they are
reported everywhere and enforced only under ``--stable-host``: a shared CI
runner cannot tell a regression from a noisy neighbour, and a threshold that
fires at random teaches reviewers to ignore the gate.

Exit status is 0 when every enforced rule holds, else 1.
"""
import argparse
import math
import os
import sys

GATE_KINDS = ("deterministic", "timing")
GATE_STATUSES = ("pass", "fail")
GATE_RELATIONS = (">=", "<=")

GATE_FIELDS = 8
METRIC_FIELDS = 4
SENTINEL_FIELDS = 3
PROVENANCE_FIELDS = 2

DECLARED_RATIO_PROFILES = {
    ("scanner", "scanner.verify_gib_per_s"): {
        "current_tier": "AVX-512",
        "baseline_tier": "AVX2",
        "current_build": "AVX512",
        "baseline_build": "AVX2",
    }
}


class RecordError(Exception):
    """A record the parser refuses to interpret."""


class Gate:
    def __init__(self, suite, name, kind, status, observed, relation, threshold):
        self.suite = suite
        self.name = name
        self.kind = kind
        self.status = status
        self.observed = observed
        self.relation = relation
        self.threshold = threshold

    @property
    def holds(self):
        """Whether observed/relation/threshold actually satisfy each other."""
        if self.relation == ">=":
            return self.observed >= self.threshold
        return self.observed <= self.threshold

    def describe(self):
        return "{0} ({1}) observed {2:g} {3} {4:g}".format(
            self.name, self.kind, self.observed, self.relation, self.threshold
        )


class Metric:
    def __init__(self, suite, name, value):
        self.suite = suite
        self.name = name
        self.value = value


def _suite(kind, suite):
    """Refuse a suite that the suite-qualified command-line grammar cannot address exactly."""
    if not suite:
        raise RecordError("{0} has an empty suite".format(kind))
    if "." in suite:
        raise RecordError("{0} suite '{1}' contains '.', which is reserved for the qualified name".format(kind, suite))


def _identity(kind, suite, name):
    """Refuse a record whose (suite, name) pair cannot be bound to by an exact requirement."""
    _suite("{0} record".format(kind), suite)
    if not name:
        raise RecordError("{0} record in suite '{1}' has an empty name".format(kind, suite))
    if not name.startswith(suite + ".") or len(name) == len(suite) + 1:
        raise RecordError(
            "{0} name '{1}' is not qualified with its suite '{2}'".format(kind, name, suite)
        )


def _number(text, field):
    try:
        value = float(text)
    except ValueError:
        raise RecordError("{0} '{1}' is not a number".format(field, text))
    if not math.isfinite(value):
        raise RecordError("{0} '{1}' is not finite".format(field, text))
    return value


def parse_records(text, origin):
    """Return (gates, metrics, tiers) for one result file, or raise RecordError."""
    gates = []
    metrics = {}
    provenance = {}
    closed = set()
    per_suite = {}
    metric_suites = set()

    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith(("#GATE", "#METRIC", "#TIER", "#BUILD", "#HOST")):
            continue
        fields = line.rstrip("\r").split("\t")
        where = "{0}:{1}".format(origin, number)

        try:
            if fields[0] == "#GATE":
                if len(fields) != GATE_FIELDS:
                    raise RecordError("gate record has {0} fields, expected {1}".format(len(fields), GATE_FIELDS))
                _, suite, name, kind, status, observed, relation, threshold = fields
                _identity("gate", suite, name)
                if kind not in GATE_KINDS:
                    raise RecordError("unknown gate kind '{0}'".format(kind))
                if status not in GATE_STATUSES:
                    raise RecordError("unknown gate status '{0}'".format(status))
                if relation not in GATE_RELATIONS:
                    raise RecordError("unknown gate relation '{0}'".format(relation))
                if suite in closed:
                    raise RecordError("gate '{0}' follows suite '{1}' sentinel".format(name, suite))
                if (suite, name) in per_suite:
                    raise RecordError("duplicate gate name '{0}' in suite '{1}'".format(name, suite))
                gate = Gate(
                    suite,
                    name,
                    kind,
                    status,
                    _number(observed, "observed"),
                    relation,
                    _number(threshold, "threshold"),
                )
                if (gate.status == "pass") != gate.holds:
                    raise RecordError(
                        "gate '{0}' reports {1} but {2:g} {3} {4:g} is {5}".format(
                            name, status, gate.observed, relation, gate.threshold, gate.holds
                        )
                    )
                per_suite[(suite, name)] = gate
                gates.append(gate)

            elif fields[0] == "#GATE-END":
                if len(fields) != SENTINEL_FIELDS:
                    raise RecordError(
                        "sentinel has {0} fields, expected {1}".format(len(fields), SENTINEL_FIELDS)
                    )
                _, suite, count = fields
                _suite("sentinel", suite)
                if suite in closed:
                    raise RecordError("suite '{0}' closed twice".format(suite))
                declared = _number(count, "count")
                seen = sum(1 for gate in gates if gate.suite == suite)
                if declared != seen:
                    raise RecordError(
                        "suite '{0}' sentinel declares {1:g} gates but {2} were recorded".format(
                            suite, declared, seen
                        )
                    )
                closed.add(suite)

            elif fields[0] == "#METRIC":
                if len(fields) != METRIC_FIELDS:
                    raise RecordError("metric has {0} fields, expected {1}".format(len(fields), METRIC_FIELDS))
                _, suite, name, value = fields
                _identity("metric", suite, name)
                if suite in closed:
                    raise RecordError("metric '{0}' follows suite '{1}' sentinel".format(name, suite))
                if not any(gate.suite == suite for gate in gates):
                    raise RecordError("metric '{0}' has no preceding gate in suite '{1}'".format(name, suite))
                identity = (suite, name)
                if identity in metrics:
                    raise RecordError("duplicate metric name '{0}' in suite '{1}'".format(name, suite))
                metrics[identity] = Metric(suite, name, _number(value, "value"))
                metric_suites.add(suite)

            elif fields[0] in ("#TIER", "#BUILD", "#HOST"):
                if len(fields) != PROVENANCE_FIELDS:
                    raise RecordError(
                        "{0} record has {1} fields, expected {2}".format(
                            fields[0][1:].lower(), len(fields), PROVENANCE_FIELDS
                        )
                    )
                if closed:
                    raise RecordError("{0} provenance follows a terminal suite sentinel".format(fields[0]))
                key = fields[0][1:].lower()
                if key in provenance:
                    raise RecordError("duplicate {0} provenance".format(key))
                if not fields[1]:
                    raise RecordError("{0} provenance is empty".format(key))
                provenance[key] = fields[1]

            else:
                raise RecordError("unknown record '{0}'".format(fields[0]))

        except RecordError as error:
            raise RecordError("{0}: {1}".format(where, error))

    if not gates:
        raise RecordError("{0}: no gate records; the run produced no evidence".format(origin))

    open_suites = sorted(({gate.suite for gate in gates} | metric_suites) - closed)
    if open_suites:
        raise RecordError(
            "{0}: no #GATE-END for suite(s) {1}; the run did not reach the end".format(origin, ", ".join(open_suites))
        )

    return gates, metrics, provenance


def read_result(path, problems):
    """Parse one result file, appending any refusal to `problems`."""
    if not os.path.isfile(path):
        problems.append("{0}: result file is missing".format(path))
        return [], {}, {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    try:
        gates, metrics, provenance = parse_records(text, path)
    except RecordError as error:
        problems.append(str(error))
        return [], {}, {}
    return gates, metrics, provenance


def parse_required_gate(spec):
    """Split a suite-qualified requirement into the exact (suite, name) pair a record must carry.

    The suite is the name's own prefix, which is the shape the ledger enforces at production time. Binding the pair
    rather than the bare name is what stops a foreign suite from answering for a gate it does not own.
    """
    suite, separator, remainder = spec.partition(".")
    if not separator or not suite or not remainder:
        raise argparse.ArgumentTypeError("expected a suite-qualified SUITE.NAME requirement, got '{0}'".format(spec))
    return suite, spec


def parse_metric_ratio(spec):
    """Split a NAME:MIN ratio specification, where NAME is suite-qualified."""
    name, separator, minimum = spec.rpartition(":")
    if not separator or not name:
        raise argparse.ArgumentTypeError("expected NAME:MIN, got '{0}'".format(spec))
    suite, qualified_name = parse_required_gate(name)
    try:
        floor = float(minimum)
    except ValueError:
        raise argparse.ArgumentTypeError("ratio floor '{0}' is not a number".format(minimum))
    if not math.isfinite(floor) or floor <= 0.0:
        raise argparse.ArgumentTypeError("ratio floor must be finite and positive, got '{0}'".format(minimum))
    return suite, qualified_name, floor


def unmet_requirements(gates, required):
    """Return requirements no deterministic gate satisfies as an exact (suite, name) pair.

    Matching the bare name would let any suite answer for another's gate. Accepting a timing gate would also let an
    advisory record satisfy release correctness on a shared host, where timing failures deliberately do not block.
    """
    present = {(gate.suite, gate.name) for gate in gates if gate.kind == "deterministic"}
    return [(suite, name) for suite, name in required if (suite, name) not in present]


def enforce_gates(gates, stable_host, problems, notes, label=""):
    """Apply deterministic and host-qualified timing policy to one evidence set."""
    prefix = "{0} ".format(label) if label else ""
    for gate in gates:
        if gate.status == "pass":
            continue
        message = "{0}{1}: {2} FAILED".format(prefix, gate.suite, gate.describe())
        if gate.kind == "deterministic" or stable_host:
            problems.append(message)
        else:
            notes.append("{0}; not enforced without --stable-host".format(message))


def build_parser():
    parser = argparse.ArgumentParser(description="Gate recorded benchmark evidence.")
    parser.add_argument("results", nargs="+", help="benchmark stdout captures to check")
    parser.add_argument(
        "--stable-host",
        action="store_true",
        help="enforce timing gates and metric ratios; only pass this on a host whose wall-clock behaviour is declared stable",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        type=parse_required_gate,
        metavar="SUITE.NAME",
        help="suite-qualified deterministic gate identity that must be present as an exact (suite, name) pair",
    )
    parser.add_argument("--baseline", metavar="FILE", help="earlier result file to compare metrics against")
    parser.add_argument(
        "--metric-ratio",
        action="append",
        default=[],
        type=parse_metric_ratio,
        metavar="NAME:MIN",
        help="require current/baseline for metric NAME to be at least MIN (needs --baseline and --stable-host)",
    )
    parser.add_argument("--current-tier", metavar="NAME", help="expected current capture #TIER")
    parser.add_argument("--baseline-tier", metavar="NAME", help="expected baseline capture #TIER")
    parser.add_argument("--current-build", metavar="ROLE", help="expected current capture #BUILD role")
    parser.add_argument("--baseline-build", metavar="ROLE", help="expected baseline capture #BUILD role")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    problems = []
    notes = []

    gates = []
    metrics = {}
    metric_sources = {}
    suite_origins = {}
    for path in args.results:
        found, measured, provenance = read_result(path, problems)
        for suite in {gate.suite for gate in found}:
            if suite in suite_origins:
                problems.append(
                    "suite '{0}' appears in both {1} and {2}; captures may not be spliced".format(
                        suite, suite_origins[suite], path
                    )
                )
            else:
                suite_origins[suite] = path
        for identity, metric in measured.items():
            if identity in metrics:
                problems.append(
                    "metric '{0}' appears in both {1} and {2}; captures may not override evidence".format(
                        metric.name, metric_sources[identity][2], path
                    )
                )
                continue
            metrics[identity] = metric
            metric_sources[identity] = (provenance, found, path)
        gates.extend(found)

    enforce_gates(gates, args.stable_host, problems, notes)

    for suite, name in unmet_requirements(gates, args.require):
        problems.append("required deterministic gate '{0}' was never recorded by suite '{1}'".format(name, suite))

    if args.metric_ratio:
        if not args.baseline:
            problems.append("--metric-ratio needs --baseline")
        else:
            baseline_gates, baseline, baseline_provenance = read_result(args.baseline, problems)
            enforce_gates(baseline_gates, args.stable_host, problems, notes, "baseline")
            metadata_args = {
                "current_tier": args.current_tier,
                "baseline_tier": args.baseline_tier,
                "current_build": args.current_build,
                "baseline_build": args.baseline_build,
            }
            missing_args = ["--" + key.replace("_", "-") for key, value in metadata_args.items() if not value]
            if missing_args:
                problems.append("--metric-ratio needs {0}".format(", ".join(missing_args)))
            for suite, name, floor in args.metric_ratio:
                identity = (suite, name)
                if identity not in metrics or identity not in baseline:
                    problems.append("metric '{0}' is missing from the current run or the baseline".format(name))
                    continue
                current_metric = metrics[identity]
                baseline_metric = baseline[identity]
                current_provenance, current_gates, current_origin = metric_sources[identity]
                if current_metric.suite != suite or baseline_metric.suite != suite:
                    problems.append(
                        "metric '{0}' was indexed for suite '{1}' but belongs to current suite '{2}' and baseline "
                        "suite '{3}'".format(
                            name, suite, current_metric.suite, baseline_metric.suite
                        )
                    )
                    # Refusing the identity and then dividing its values anyway would report a ratio between two
                    # metrics this branch just said do not answer for the requested suite.
                    continue
                current_scenarios = {
                    gate.name
                    for gate in current_gates
                    if gate.suite == current_metric.suite and gate.kind == "deterministic"
                }
                baseline_scenarios = {
                    gate.name
                    for gate in baseline_gates
                    if gate.suite == baseline_metric.suite and gate.kind == "deterministic"
                }
                if not current_scenarios or current_scenarios != baseline_scenarios:
                    problems.append(
                        "metric '{0}' current/baseline deterministic scenarios differ or are empty".format(name)
                    )

                expected = dict(metadata_args)
                declared = DECLARED_RATIO_PROFILES.get(identity)
                if declared:
                    for key, value in declared.items():
                        if expected.get(key) and expected[key] != value:
                            problems.append(
                                "metric '{0}' declares {1} '{2}', not '{3}'".format(
                                    name, key.replace("_", " "), value, expected[key]
                                )
                            )
                        expected[key] = value

                for side, provenance, origin in (
                    ("current", current_provenance, current_origin),
                    ("baseline", baseline_provenance, args.baseline),
                ):
                    for field in ("tier", "build"):
                        wanted = expected.get("{0}_{1}".format(side, field))
                        observed = provenance.get(field)
                        if not observed:
                            problems.append("{0}: metric '{1}' has no #{2}".format(origin, name, field.upper()))
                        elif wanted and observed != wanted:
                            problems.append(
                                "{0}: metric '{1}' has {2} '{3}', expected '{4}'".format(
                                    origin, name, field, observed, wanted
                                )
                            )
                current_host = current_provenance.get("host")
                baseline_host = baseline_provenance.get("host")
                if not current_host or not baseline_host:
                    problems.append("metric '{0}' needs nonempty #HOST provenance in both captures".format(name))
                elif current_host != baseline_host:
                    problems.append(
                        "metric '{0}' host mismatch: current '{1}', baseline '{2}'".format(
                            name, current_host, baseline_host
                        )
                    )

                if current_metric.value <= 0.0 or baseline_metric.value <= 0.0:
                    problems.append("metric '{0}' ratio operands must be finite and positive".format(name))
                    continue
                ratio = current_metric.value / baseline_metric.value
                message = "metric {0} ratio {1:.4f} < {2:g}".format(name, ratio, floor)
                if ratio >= floor:
                    continue
                if args.stable_host:
                    problems.append(message)
                else:
                    notes.append("{0}; not enforced without --stable-host".format(message))

    for note in notes:
        print("note: {0}".format(note))

    if problems:
        print("Benchmark evidence rejected:")
        for problem in problems:
            print("  {0}".format(problem))
        return 1

    print(
        "Benchmark evidence OK: {0} gate(s) across {1} suite(s){2}.".format(
            len(gates),
            len({gate.suite for gate in gates}),
            "" if args.stable_host else ", timing gates recorded but not enforced",
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
