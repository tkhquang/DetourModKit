#!/usr/bin/env python3
"""Gate that one named GoogleTest case really executed and published its evidence marker.

A case that fails is red, and a case that never ran is green. That asymmetry is
what makes a host-conditional proof unusable as release evidence: the fixed-base
replacement case calls ``GTEST_SKIP()`` when the loader will not place its two
variants at the reserved base, so a candidate host that cannot map them reports
the same "0 failed" a host that proved the contract reports.

This checker reads a GoogleTest XML report and refuses everything that is not an
executed pass of the exact named case:

  - a report that is missing, unreadable, or not parsable XML
  - the case absent from the report, or present more than once
  - the case recorded with neither a status nor a result, which states nothing
  - the case recorded as not run, suppressed, or skipped
  - the case carrying a ``failure`` or ``error`` result, whatever else it claims
  - the case missing the required property, or carrying a different value

The property is the half a rerun cannot fake: the case publishes it only after
its own preconditions were observed, so a case that ran, took an early exit, and
still reported green has no marker and is refused here.

``--skip-exit-code`` is for the ordinary developer tree, where the mapping is
genuinely unavailable and Skipped is the honest outcome. Release preflight runs
the exact case WITHOUT it, so an unavailable mapping is a red candidate host.

Exit status is 0 when the case executed and published the marker, the
``--skip-exit-code`` value when the case skipped and that option was given,
else 1.
"""
import argparse
import os
import sys
import xml.etree.ElementTree as ElementTree

# GoogleTest writes result="completed" for a case that ran to its end. Older reports carry status but no result.
EXECUTED_RESULTS = ("completed",)
SKIPPED_RESULTS = ("skipped",)


def parse_property(text):
    """Split a NAME=VALUE property requirement."""
    name, separator, value = text.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError("expected NAME=VALUE, got '{0}'".format(text))
    return name, value


def parse_case(text):
    """Split a Suite.Case requirement into its GoogleTest classname and name."""
    classname, separator, name = text.rpartition(".")
    if not separator or not classname or not name:
        raise argparse.ArgumentTypeError("expected Suite.Case, got '{0}'".format(text))
    return classname, name


def matching_cases(root, classname, name):
    """Return every ``testcase`` element whose exact classname and name match."""
    return [
        case
        for case in root.iter("testcase")
        if case.get("classname") == classname and case.get("name") == name
    ]


def records_outcome(case):
    """Whether the case carries a recorded failure or error."""
    return any(case.find(outcome) is not None for outcome in ("failure", "error"))


def is_skipped(case):
    """Whether the report records the case as skipped rather than executed.

    A case that also records a failure or an error is not a skip whatever else it claims: `--skip-exit-code` exists
    for a host that could not run the case, and a recorded outcome says it ran. Deciding that here rather than at the
    exit-code branch keeps the one thing the skip code may launder to exactly one shape.
    """
    if records_outcome(case):
        return False
    return case.get("result") in SKIPPED_RESULTS or case.find("skipped") is not None


def published_property(case, name):
    """Return the value the case published for `name`, or None.

    GoogleTest writes test properties as a ``<properties><property/></properties>`` child element; reports from older
    writers carried them as attributes on ``<testcase>`` itself. Read both, so this checker is not pinned to one era
    of the report format.
    """
    container = case.find("properties")
    if container is not None:
        for entry in container.iter("property"):
            if entry.get("name") == name:
                return entry.get("value")
    return case.get(name)


def check_case(case, wanted, problems):
    """Append every reason `case` is not an executed, marked pass of the required case."""
    label = "{0}.{1}".format(case.get("classname"), case.get("name"))

    status = case.get("status")
    result = case.get("result")
    if status is None and result is None:
        problems.append(
            "case '{0}' records neither a status nor a result, so the report never says it ran".format(label)
        )
        return
    if status is not None and status != "run":
        problems.append("case '{0}' has status '{1}', so it never executed".format(label, status))
        return
    if result is not None and result not in EXECUTED_RESULTS:
        problems.append("case '{0}' has result '{1}', so it did not run to completion".format(label, result))
        return
    for outcome in ("failure", "error"):
        if case.find(outcome) is not None:
            problems.append("case '{0}' records a {1}".format(label, outcome))

    for property_name, expected in wanted:
        observed = published_property(case, property_name)
        if observed is None:
            problems.append(
                "case '{0}' published no '{1}' property, so it reported green without reaching the "
                "observation that publishes it".format(label, property_name)
            )
        elif observed != expected:
            problems.append(
                "case '{0}' published '{1}' = '{2}', expected '{3}'".format(label, property_name, observed, expected)
            )


def check_report(path, classname, name, wanted, problems):
    """Parse one report and apply every rule, returning whether the named case skipped."""
    if not os.path.isfile(path):
        problems.append("{0}: report is missing; nothing recorded that the case ran".format(path))
        return False
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError as error:
        problems.append("{0}: report is not parsable XML ({1})".format(path, error))
        return False

    cases = matching_cases(root, classname, name)
    if not cases:
        problems.append("{0}: case '{1}.{2}' is absent from the report".format(path, classname, name))
        return False
    if len(cases) > 1:
        problems.append(
            "{0}: case '{1}.{2}' appears {3} times; the evidence does not name one execution".format(
                path, classname, name, len(cases)
            )
        )
        return False

    case = cases[0]
    if is_skipped(case):
        problems.append(
            "{0}: case '{1}.{2}' was skipped, so this host proved nothing about it".format(path, classname, name)
        )
        return True

    check_case(case, wanted, problems)
    return False


def build_parser():
    parser = argparse.ArgumentParser(description="Gate an exact executed, non-skipped GoogleTest proof.")
    parser.add_argument("report", help="GoogleTest XML report to read")
    parser.add_argument("--case", required=True, type=parse_case, metavar="SUITE.CASE", help="exact case that must run")
    parser.add_argument(
        "--property",
        action="append",
        default=[],
        required=True,
        type=parse_property,
        metavar="NAME=VALUE",
        help="property the case must publish, with its exact value",
    )
    parser.add_argument(
        "--skip-exit-code",
        type=int,
        metavar="CODE",
        help="exit with CODE instead of 1 when the case skipped; omit it on a candidate host, where a skip is red",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    classname, name = args.case

    problems = []
    skipped = check_report(args.report, classname, name, args.property, problems)

    if problems:
        print("GoogleTest execution evidence rejected:")
        for problem in problems:
            print("  {0}".format(problem))
        if skipped and args.skip_exit_code is not None:
            return args.skip_exit_code
        return 1

    print(
        "GoogleTest execution evidence OK: {0}.{1} executed and published {2}.".format(
            classname, name, ", ".join("{0}={1}".format(key, value) for key, value in args.property)
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
