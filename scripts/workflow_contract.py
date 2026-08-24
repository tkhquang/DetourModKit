#!/usr/bin/env python3
"""The canonical shape of this repository's workflows, as data.

`check_workflow_topology.py` decides nothing from spelling it finds in a workflow: it decides by
comparing the workflow against what is written here. Keeping the two apart is what makes the checker
a comparison rather than a search. A search can only ask whether something it recognizes is present,
which is answered "yes" by a mutated program that still contains the fragment; a comparison asks
whether the program IS the reviewed one, which a mutation cannot answer "yes" to by adding anything.

Every entry is bidirectional. A job, step, shell, or condition that appears in a workflow and not
here is unreviewed and refused; one that appears here and not in the workflow has been deleted or
renamed and is refused. Changing a workflow therefore means changing this file in the same review.

`program` gives load-bearing steps an explicit ordered-line contract and targeted diagnostics. The
canonical source digest additionally pins every workflow byte after newline normalization, including
every other run body, action reference/input, trigger value, matrix, permission, default, and output.
"""
from dataclasses import dataclass


QUALITY = ".github/workflows/quality.yml"
SIMD = ".github/workflows/simd-tier-correctness.yml"
RELEASE = ".github/workflows/release.yml"
PR_CHECK = ".github/workflows/pr-check.yml"
ARCH_GATE = ".github/workflows/arch-gate.yml"
SANITIZERS = ".github/workflows/sanitizers.yml"
COVERAGE_PAGES = ".github/workflows/coverage-pages.yml"

# The shells a required step may declare. A step's shell decides how its exit status reaches the job,
# so a custom template (`bash {0} || true` and its relatives) is not a shell choice but a status
# rewrite, and `sh` is excluded because GitHub runs it without pipefail.
# Every run step below records its shell explicitly, so GitHub's runner default is never the value a
# step is checked against: dropping a `shell` key is a mismatch against the reviewed one, not a fallback.
REVIEWED_SHELLS = ("bash", "cmd", "pwsh", "powershell")

BLOCKING_QUALITY_JOBS = (
    "format-check",
    "clang-tidy",
    "header-hygiene",
    "mechanical-style",
    "backend-patch",
    "workflow-contract",
)
REQUIRED_RELEASE_JOBS = ("validate-version", "build-mingw", "build-msvc", "benchmark-evidence", "create-release")
PUBLISH_MODE_CONDITION = "${{ inputs.mode == 'publish' }}"

TAG_STEP = "Create or verify annotated tag"
IDENTITY_STEP = "Assert the dispatch resolved to the exact candidate"
DISPATCH_IDENTITY_STEP = "Assert the manual dispatch resolved to the exact candidate"
REF_GUARD_STEP = "Assert the dispatch ref may publish a tag"

# The two credentialed inputs, and the only steps allowed to carry one.
RELEASE_TOKEN_STEPS = ("Checkout code for annotated tag", "Create GitHub Release")
RELEASE_TOKEN_VALUE = "${{ secrets.RELEASE_TOKEN }}"

# The dispatch identity command, shared by every context that can be dispatched at a final candidate.
# `github.event.inputs` and `inputs` are the same value; each workflow keeps the spelling it uses.
DISPATCH_IDENTITY_PROGRAM = (
    'python scripts/check_release_identity.py --expected-sha "$EXPECTED_SHA" '
    '--event-sha "$EVENT_SHA" --verify-checkout',
)
RELEASE_IDENTITY_PROGRAM = (
    'python scripts/check_release_identity.py --expected-sha "$EXPECTED_SHA" '
    '--event-sha "$EVENT_SHA" --verify-checkout',
)
RELEASE_REF_GUARD_PROGRAM = (
    'python scripts/check_release_identity.py --expected-sha "$EXPECTED_SHA" '
    '--event-sha "$EVENT_SHA" --verify-checkout --required-ref refs/heads/main --actual-ref "$ACTUAL_REF"',
)

DISPATCH_IDENTITY_ENVIRONMENT = (
    ("EVENT_SHA", "${{ github.sha }}"),
    ("EXPECTED_SHA", "${{ inputs.expected_sha }}"),
)
RELEASE_IDENTITY_ENVIRONMENT = (
    ("EVENT_SHA", "${{ github.sha }}"),
    ("EXPECTED_SHA", "${{ github.event.inputs.expected_sha }}"),
)
RELEASE_REF_GUARD_ENVIRONMENT = (
    ("ACTUAL_REF", "${{ github.ref }}"),
    ("EVENT_SHA", "${{ github.sha }}"),
    ("EXPECTED_SHA", "${{ github.event.inputs.expected_sha }}"),
)

# The publication program. Its ordering is the contract, not only its contents: the single success
# branch returns early ONLY after the remote tag has been observed to resolve to the candidate, so the
# same lines in a different order are a different, and wrong, program.
TAG_PROGRAM = (
    'TITLE="${RELEASE_TITLE}"',
    'VERSION="v${RELEASE_VERSION}"',
    'TAG_MESSAGE="${TITLE:-DetourModKit ${VERSION}}"',
    'REMOTE_REF="$(git ls-remote --tags origin "refs/tags/${VERSION}" | awk \'NR == 1 { print $1 }\')"',
    'REMOTE_TARGET="$(git ls-remote --tags origin "refs/tags/${VERSION}^{}" | awk \'NR == 1 { print $1 }\')"',
    'if [ -n "${REMOTE_REF}" ] && [ -z "${REMOTE_TARGET}" ]; then',
    'echo "::error::Existing tag ${VERSION} is lightweight; the release contract requires an annotated tag."',
    "exit 1",
    "fi",
    'if [ -n "${REMOTE_TARGET}" ]; then',
    'if [ "${REMOTE_TARGET}" != "${EXPECTED_SHA}" ]; then',
    'echo "::error::Existing tag ${VERSION} resolves to ${REMOTE_TARGET}, not exact candidate ${EXPECTED_SHA}."',
    "exit 1",
    "fi",
    'echo "Existing tag ${VERSION} already resolves to the exact candidate;" '
    '"reusing it after a prior partial run."',
    "exit 0",
    "fi",
    'git config user.name "Quang Trinh"',
    'git config user.email "khacquang.trinh@gmail.com"',
    'git tag -a "$VERSION" -m "$TAG_MESSAGE" "${EXPECTED_SHA}"',
    'git push origin "refs/tags/${VERSION}"',
)

TAG_ENVIRONMENT = (
    ("EXPECTED_SHA", "${{ github.sha }}"),
    ("RELEASE_TITLE", "${{ github.event.inputs.release_title }}"),
    ("RELEASE_VERSION", "${{ github.event.inputs.version }}"),
)

SAME_BASE_CASE = "MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent"
SAME_BASE_PROPERTY = "dmk_same_base_replacement=executed"


def same_base_program(build_directory):
    return (
        "python scripts/check_gtest_execution.py {0}/dmk_same_base_replacement.xml "
        "--case {1} --property {2}".format(build_directory, SAME_BASE_CASE, SAME_BASE_PROPERTY),
    )


def soak_program(build_directory, dump_directory):
    return (
        'python scripts/run_lifecycle_soak.py --build-directory "{0}" --dump-directory "{1}"'.format(
            build_directory, dump_directory
        ),
    )


BENCHMARK_BUILD_PROGRAM = (
    "cmake --preset mingw-release -DDMK_BUILD_BENCHMARKS=ON",
    "cmake --build build/mingw-release --parallel --target DetourModKit_bench DetourModKit_bench_scanner "
    "DetourModKit_bench_memory DetourModKit_bench_logger DetourModKit_bench_footprint "
    "DetourModKit_corpus_sighealth dmk_bench_gate_probe",
)

BENCHMARK_CHECK_PROGRAM = (
    "LEDGER_PROBE=\"$(find build/mingw-release -name 'dmk_bench_gate_probe.exe' -type f | head -n 1)\"",
    'if [ -z "${LEDGER_PROBE}" ]; then',
    'echo "::error::No dmk_bench_gate_probe.exe under build/mingw-release; the producer boundary was not built."',
    "exit 1",
    "fi",
    'python scripts/test_check_benchmark_results.py --ledger-probe "${LEDGER_PROBE}"',
    "python scripts/check_benchmark_results.py bench-results/*.txt "
    "--require scanner.scenario_anchor_agreement --require scanner.verify_workload_no_match "
    "--require scanner.resolver_batch_matches_serial --require memory.chain_walk_resolves_leaf "
    "--require memory.cache_shutdown_releases_heap "
    "--require logger.enqueue_reached_the_queue --require dispatcher.reentrant_subscribe_rejected "
    "--require footprint.profiler_record_allocation_free "
    "--require corpus.canonical_prologue_exceeds_fail_threshold",
)

# Three steps whose bodies a token scanner cannot read: PowerShell treats a trailing backslash inside a
# string as data where a POSIX lexer reads an escaped quote, and an embedded `python -c` script is not a
# shell program at all. A body the scanner cannot decide is pinned exactly instead of waved through,
# which is the stronger of the two boundaries anyway.
PR_CHECK_RUNTIME_DLL_PROGRAM = (
    '$testDir = "build\\mingw-debug\\tests"',
    "$mingwBin = Split-Path -Parent (Get-Command g++).Source",
    'Get-ChildItem "$mingwBin\\lib*.dll" -ErrorAction SilentlyContinue | ForEach-Object {',
    'Copy-Item $_.FullName "$testDir\\"',
    "}",
)

COVERAGE_RUNTIME_DLL_PROGRAM = (
    '$testDir = "build\\mingw-debug\\tests"',
    'Get-ChildItem "${{ env.MINGW_BIN }}\\lib*.dll" | ForEach-Object {',
    'Copy-Item $_.FullName "$testDir\\"',
    "}",
)

COVERAGE_THRESHOLD_PROGRAM = (
    'LINE_RATE=$(python -c "',
    "import xml.etree.ElementTree as ET",
    "tree = ET.parse('coverage.xml')",
    "root = tree.getroot()",
    "rate = float(root.attrib.get('line-rate', 0))",
    "print(f'{rate * 100:.2f}')",
    '")',
    'echo "Line coverage: ${LINE_RATE}%"',
    'python -c "',
    "rate = float('${LINE_RATE}')",
    "if rate < 80.0:",
    "print(f'FAIL: Coverage {rate:.2f}% is below 80% threshold')",
    "exit(1)",
    "else:",
    "print(f'PASS: Coverage {rate:.2f}% meets 80% threshold')",
    '"',
)

MINGW_BUILD_TREE_PROGRAM = (
    "cmake -S tests/package_build_tree -B build/package-build-tree-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release "
    "-DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DDMK_WARNINGS_AS_ERRORS=ON",
    "cmake --build build/package-build-tree-mingw --parallel 4",
    "ctest --test-dir build/package-build-tree-mingw --output-on-failure",
)

MSVC_BUILD_TREE_PROGRAM = (
    "cmake -S tests/package_build_tree -B build/package-build-tree-msvc -G Ninja -DCMAKE_BUILD_TYPE=Release "
    "-DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DDMK_WARNINGS_AS_ERRORS=ON",
    "if errorlevel 1 exit /b 1",
    "cmake --build build/package-build-tree-msvc --parallel 2",
    "if errorlevel 1 exit /b 1",
    "ctest --test-dir build/package-build-tree-msvc --output-on-failure",
)

# `X="$(cmd || true)"` turns a failure into an empty VALUE that the next guard still has to decide on,
# which is a different construct from a bare statement whose failure reaches nothing. Allowed by exact
# line so the carve-out cannot widen into "captures are fine".
ALLOWED_FAILURE_CAPTURES = (
    r'''TEST_MAJOR="$(grep -m1 -oP 'DMK_VERSION_MAJOR,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
    r'''TEST_MINOR="$(grep -m1 -oP 'DMK_VERSION_MINOR,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
    r'''TEST_PATCH="$(grep -m1 -oP 'DMK_VERSION_PATCH,\s*\K[0-9]+' tests/test_version.cpp || true)"''',
)

# The step that owns the sole reviewed `exit 0`. Everywhere else a bare success exit skips what it covers.
ALLOWED_SUCCESS_EXIT_STEPS = ((RELEASE, "create-release", TAG_STEP),)


@dataclass(frozen=True)
class Step:
    """One reviewed step.

    `shell` is None for an action step, which must then declare no shell and no run body.
    `condition` is None when the step must be unconditional. `environment` is None when the step's
    env block is not pinned, and an exact tuple of pairs (possibly empty) when it is.
    """

    name: str
    shell: str = None
    condition: str = None
    program: tuple = None
    environment: tuple = None
    working_directory: str = None


@dataclass(frozen=True)
class Job:
    runner: str
    condition: str = None
    needs: tuple = ()
    steps: tuple = ()


@dataclass(frozen=True)
class WorkflowShape:
    """One workflow's reviewed triggers and jobs.

    `path_filtered_triggers` names the triggers allowed to carry a paths filter. Any other trigger
    that carries one is refused: a required context that a paths filter prevented from being created
    leaves a pull request waiting forever for a check that will never report.
    """

    triggers: tuple
    jobs: tuple
    path_filtered_triggers: tuple = ()


CHECKOUT = Step("Checkout code")


WORKFLOWS = {
    RELEASE: WorkflowShape(
        triggers=("workflow_dispatch",),
        jobs=(
            (
                "validate-version",
                Job(
                    runner="ubuntu-latest",
                    steps=(
                        CHECKOUT,
                        Step(
                            IDENTITY_STEP,
                            shell="bash",
                            program=RELEASE_IDENTITY_PROGRAM,
                            environment=RELEASE_IDENTITY_ENVIRONMENT,
                        ),
                        Step("Compare release input against project(VERSION) in CMakeLists.txt", shell="bash"),
                    ),
                ),
            ),
            (
                "build-mingw",
                Job(
                    runner="windows-2022",
                    needs=("validate-version",),
                    steps=(
                        CHECKOUT,
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Install Ninja and CMake", shell="powershell"),
                        Step("Verify Tools (MinGW context)", shell="bash"),
                        Step("Configure DetourModKit (MinGW Debug + Tests)", shell="bash"),
                        Step("Build DetourModKit (MinGW Debug + Tests)", shell="bash"),
                        Step("Run DetourModKit Tests (MinGW Debug)", shell="bash"),
                        Step("Configure DetourModKit (MinGW Release)", shell="bash"),
                        Step("Build DetourModKit (MinGW Release)", shell="bash"),
                        Step("Run DetourModKit Tests (MinGW Release)", shell="bash"),
                        Step(
                            "Assert the same-base replacement case executed (MinGW Release)",
                            shell="bash",
                            program=same_base_program("build/mingw-release"),
                        ),
                        Step(
                            "Run dump-capturing lifecycle soak (MinGW Release)",
                            shell="bash",
                            program=soak_program("build/mingw-release", "$RUNNER_TEMP/dmk-lifecycle-dumps-mingw"),
                        ),
                        Step("Upload MinGW lifecycle failure diagnostics", condition="failure()"),
                        Step("Configure DetourModKit Package Producer (MinGW Release, tests OFF)", shell="bash"),
                        Step("Build DetourModKit Package Producer (MinGW Release)", shell="bash"),
                        Step("Install DetourModKit (MinGW Release)", shell="bash"),
                        Step("Assert Export Equality (MinGW)", shell="bash"),
                        Step("Verify Install Directory (MinGW)", shell="pwsh"),
                        Step("Assert Install-Prefix Hygiene (MinGW)", shell="bash"),
                        Step("Assert No Test Seams (MinGW)", shell="bash"),
                        Step("Assert Emit Path Has No Emulated TLS (MinGW)", shell="bash"),
                        Step("Smoke Test Installed Package (MinGW)", shell="bash"),
                        Step(
                            "Build-Tree Consumer Proof (MinGW)",
                            shell="bash",
                            program=MINGW_BUILD_TREE_PROGRAM,
                        ),
                        Step("Dual-Config Package Matrix (MinGW)", shell="bash"),
                        Step("Determine Artifact Name (MinGW)", shell="pwsh"),
                        Step("Create ZIP archive (MinGW)", shell="pwsh"),
                        Step("Upload MinGW Artifact for Release"),
                    ),
                ),
            ),
            (
                "build-msvc",
                Job(
                    runner="windows-2022",
                    needs=("validate-version",),
                    steps=(
                        CHECKOUT,
                        Step("Install Ninja and CMake", shell="powershell"),
                        Step("Setup MSVC Developer Environment"),
                        Step("Verify Tools (MSVC context)", shell="bash"),
                        Step("Configure DetourModKit (MSVC Debug + Tests)", shell="cmd"),
                        Step("Build DetourModKit (MSVC Debug + Tests)", shell="cmd"),
                        Step("Run DetourModKit Tests (MSVC Debug)", shell="cmd"),
                        Step("Configure DetourModKit (MSVC Release)", shell="cmd"),
                        Step("Build DetourModKit (MSVC Release)", shell="cmd"),
                        Step("Run DetourModKit Tests (MSVC Release)", shell="cmd"),
                        Step(
                            "Assert the same-base replacement case executed (MSVC Release)",
                            shell="bash",
                            program=same_base_program("build/msvc-release"),
                        ),
                        Step(
                            "Run dump-capturing lifecycle soak (MSVC Release)",
                            shell="bash",
                            program=soak_program("build/msvc-release", "$RUNNER_TEMP/dmk-lifecycle-dumps-msvc"),
                        ),
                        Step("Upload MSVC lifecycle failure diagnostics", condition="failure()"),
                        Step("Configure DetourModKit Package Producer (MSVC Release, tests OFF)", shell="cmd"),
                        Step("Build DetourModKit Package Producer (MSVC Release)", shell="cmd"),
                        Step("Install DetourModKit (MSVC Release)", shell="cmd"),
                        Step("Assert Export Equality (MSVC)", shell="bash"),
                        Step("Verify Install Directory (MSVC)", shell="pwsh"),
                        Step("Assert Install-Prefix Hygiene (MSVC)", shell="bash"),
                        Step("Assert No Test Seams (MSVC)", shell="bash"),
                        Step("Smoke Test Installed Package (MSVC)", shell="cmd"),
                        Step(
                            "Build-Tree Consumer Proof (MSVC)",
                            shell="cmd",
                            program=MSVC_BUILD_TREE_PROGRAM,
                        ),
                        Step("Dual-Config Package Matrix (MSVC)", shell="cmd"),
                        Step("Determine Artifact Name (MSVC)", shell="pwsh"),
                        Step("Create ZIP archive (MSVC)", shell="pwsh"),
                        Step("Upload MSVC Artifact for Release"),
                    ),
                ),
            ),
            (
                "benchmark-evidence",
                Job(
                    runner="windows-2022",
                    needs=("validate-version",),
                    steps=(
                        CHECKOUT,
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Install Ninja and CMake", shell="powershell"),
                        Step("Verify Tools (MinGW context)", shell="bash"),
                        Step(
                            "Configure and build the benchmarks (MinGW Release)",
                            shell="bash",
                            program=BENCHMARK_BUILD_PROGRAM,
                        ),
                        Step("Run the benchmarks", shell="bash"),
                        Step("Check the recorded evidence", shell="bash", program=BENCHMARK_CHECK_PROGRAM),
                        Step("Upload benchmark evidence", condition="${{ !cancelled() }}"),
                    ),
                ),
            ),
            (
                "create-release",
                Job(
                    runner="ubuntu-latest",
                    condition=PUBLISH_MODE_CONDITION,
                    needs=("benchmark-evidence", "build-mingw", "build-msvc"),
                    steps=(
                        Step("Checkout code for the release identity guard"),
                        Step(
                            REF_GUARD_STEP,
                            shell="bash",
                            program=RELEASE_REF_GUARD_PROGRAM,
                            environment=RELEASE_REF_GUARD_ENVIRONMENT,
                        ),
                        Step("Download MinGW artifact"),
                        Step("Download MSVC artifact"),
                        Step("List downloaded artifacts for verification", shell="bash"),
                        Step("Prepare file list for release", shell="bash"),
                        Step("Checkout code for annotated tag"),
                        Step(
                            TAG_STEP,
                            shell="bash",
                            program=TAG_PROGRAM,
                            environment=TAG_ENVIRONMENT,
                            working_directory="release-source",
                        ),
                        Step("Create GitHub Release"),
                    ),
                ),
            ),
        ),
    ),
    QUALITY: WorkflowShape(
        triggers=("pull_request", "workflow_dispatch"),
        jobs=(
            (
                "format-check",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Install clang-format", shell="bash"),
                        Step("Check formatting (dry run, project sources only)", shell="bash"),
                        Step("Check comment-marker conventions", shell="bash", condition="${{ !cancelled() }}"),
                    ),
                ),
            ),
            (
                "header-hygiene",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(CHECKOUT, Step("Check header-encapsulation hygiene", shell="bash")),
                ),
            ),
            (
                "mechanical-style",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(CHECKOUT, Step("Check mechanical naming/namespace/dash rules", shell="bash")),
                ),
            ),
            (
                "backend-patch",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Self-test the backend-patch checker", shell="bash"),
                        Step("Check the pristine pinned backend input", shell="bash", condition="${{ !cancelled() }}"),
                        Step(
                            "Apply the vendored patch the way a configure does",
                            shell="bash",
                            condition="${{ !cancelled() }}",
                        ),
                        Step(
                            "Re-run the configure boundary on the configured backend",
                            shell="bash",
                            condition="${{ !cancelled() }}",
                        ),
                        Step(
                            "Check the configured backend equals the reviewed patch output",
                            shell="bash",
                            condition="${{ !cancelled() }}",
                        ),
                    ),
                ),
            ),
            (
                "workflow-contract",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step(
                            "Self-test the workflow topology checker",
                            shell="bash",
                            program=("python scripts/test_check_workflow_topology.py",),
                        ),
                        Step(
                            "Self-test the release identity checker",
                            shell="bash",
                            condition="${{ !cancelled() }}",
                            program=("python scripts/test_check_release_identity.py",),
                        ),
                        Step(
                            "Check this repository against the canonical workflow contract",
                            shell="bash",
                            condition="${{ !cancelled() }}",
                            program=("python scripts/check_workflow_topology.py --repository-root .",),
                        ),
                    ),
                ),
            ),
            (
                "clang-tidy",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Install clang-tidy", shell="bash"),
                        Step("Configure (compile database only, library sources)", shell="bash"),
                        Step("Analyse library sources (warnings are errors)", shell="bash"),
                    ),
                ),
            ),
        ),
    ),
    PR_CHECK: WorkflowShape(
        triggers=("pull_request", "workflow_dispatch"),
        jobs=(
            (
                "build-test",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Cache pip packages"),
                        Step("Install gcovr", shell="powershell"),
                        Step("Cache CMake build"),
                        Step("Verify Tools", shell="bash"),
                        Step("Configure (Debug + Tests + Coverage)", shell="bash"),
                        Step("Build", shell="bash"),
                        Step("Copy MinGW runtime DLLs", shell="powershell", program=PR_CHECK_RUNTIME_DLL_PROGRAM),
                        Step("Run Tests", shell="bash", program=("ctest --preset mingw-debug",)),
                        Step("Generate Coverage Report", shell="bash"),
                        Step("Check Coverage Threshold (80%)", shell="bash", program=COVERAGE_THRESHOLD_PROGRAM),
                        Step("Build-Tree Consumer Proof (MinGW)", shell="bash"),
                        Step("Dual-Config Package Matrix (MinGW)", shell="bash"),
                        Step("Upload Coverage Report", condition="always()"),
                    ),
                ),
            ),
            (
                "msvc-build-test",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Set up MSVC developer environment"),
                        Step("Verify Tools", shell="bash"),
                        Step("Configure (MSVC Debug + Tests, warnings as errors)", shell="cmd"),
                        Step("Build", shell="cmd"),
                        # Pinned exactly because the removed defect was a retry policy, not a respelling:
                        # `--repeat until-pass` reports green on a second attempt and normalizes a red gate.
                        Step("Run Tests", shell="cmd", program=("ctest --preset msvc-debug",)),
                        Step("Build-Tree Consumer Proof (MSVC)", shell="cmd"),
                        Step("Dual-Config Package Matrix (MSVC)", shell="cmd"),
                    ),
                ),
            ),
            (
                "system-zydis-package",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw-system-zydis.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Build and install pinned Zydis", shell="bash"),
                        Step("Build and consume the system-Zydis package", shell="bash"),
                    ),
                ),
            ),
            (
                "gtest-routes",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    needs=("build-test",),
                    steps=(
                        CHECKOUT,
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step(
                            "Provision a system GoogleTest (system route only)",
                            shell="bash",
                            condition="matrix.route == 'system'",
                        ),
                        Step("Configure (route = ${{ matrix.route }})", shell="bash"),
                        Step("Assert the intended route resolved", shell="bash"),
                        Step(
                            "Build proof targets",
                            shell="bash",
                            program=(
                                "cmake --build build/mingw-debug "
                                "--target dmk_fault_proof_hosts dmk_lifecycle_proof_hosts --parallel 4",
                            ),
                        ),
                        Step(
                            "Run proof cases (fault, lifecycle, timeout control)",
                            shell="bash",
                            program=(
                                'ctest --test-dir build/mingw-debug -L "fault-proof|lifecycle-proof|timeout-control" '
                                "--output-on-failure",
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ),
    ARCH_GATE: WorkflowShape(
        triggers=("pull_request", "workflow_dispatch"),
        jobs=(
            (
                "arch-gate",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step(
                            DISPATCH_IDENTITY_STEP,
                            shell="bash",
                            condition="${{ github.event_name == 'workflow_dispatch' }}",
                            program=DISPATCH_IDENTITY_PROGRAM,
                            environment=DISPATCH_IDENTITY_ENVIRONMENT,
                        ),
                        Step("Cache MinGW"),
                        Step(
                            "Install MinGW (if not cached)",
                            shell="powershell",
                            condition="steps.cache-mingw.outputs.cache-hit != 'true'",
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step(
                            "Run x86-64 architecture-gate check",
                            shell="bash",
                            program=("bash scripts/check_arch_gate.sh",),
                        ),
                    ),
                ),
            ),
        ),
    ),
    SANITIZERS: WorkflowShape(
        triggers=("pull_request", "workflow_dispatch"),
        jobs=(
            (
                "sanitizers",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step(
                            DISPATCH_IDENTITY_STEP,
                            shell="bash",
                            condition="${{ github.event_name == 'workflow_dispatch' }}",
                            program=DISPATCH_IDENTITY_PROGRAM,
                            environment=DISPATCH_IDENTITY_ENVIRONMENT,
                        ),
                        Step("Set up MSVC (x64) -- puts cl and the ASan runtime on PATH"),
                        Step("Configure (MSVC Debug + ASan)", shell="pwsh"),
                        Step("Build", shell="pwsh"),
                        Step(
                            "Run tests under ASan",
                            shell="pwsh",
                            program=("ctest --preset msvc-debug-asan --output-on-failure",),
                        ),
                        # The deliberate-red pair is opt-in evidence, not a gate: both legs stay exactly on the
                        # reviewed dispatch tuple so neither can be turned on by a push or a pull request.
                        Step(
                            "Build deliberate ASan failure probe",
                            shell="pwsh",
                            condition="${{ github.event_name == 'workflow_dispatch' && inputs.deliberate_asan_red }}",
                        ),
                        Step(
                            "Run deliberate ASan failure probe (expected red)",
                            shell="pwsh",
                            condition="${{ github.event_name == 'workflow_dispatch' && inputs.deliberate_asan_red }}",
                        ),
                    ),
                ),
            ),
        ),
    ),
    SIMD: WorkflowShape(
        triggers=("pull_request", "workflow_dispatch"),
        # Not a ruleset-required context, so its paths filter cannot strand a pull request on a missing check.
        path_filtered_triggers=("pull_request",),
        jobs=(
            (
                "tier-correctness-sde",
                Job(
                    runner="windows-latest",
                    condition="${{ !github.event.pull_request.draft }}",
                    steps=(
                        CHECKOUT,
                        Step(
                            DISPATCH_IDENTITY_STEP,
                            shell="bash",
                            condition="${{ github.event_name == 'workflow_dispatch' }}",
                            program=DISPATCH_IDENTITY_PROGRAM,
                            environment=DISPATCH_IDENTITY_ENVIRONMENT,
                        ),
                        Step("Set up MSVC (x64)"),
                        Step("Configure (MSVC Debug + AVX-512 tier)", shell="pwsh"),
                        Step("Build tests", shell="pwsh"),
                        Step("Set up Intel SDE"),
                        Step(
                            "Run ScannerTest under Intel SDE (${{ matrix.tier }} via -${{ matrix.chip }})",
                            shell="pwsh",
                        ),
                    ),
                ),
            ),
        ),
    ),
    COVERAGE_PAGES: WorkflowShape(
        triggers=("push", "workflow_dispatch"),
        # The push route republishes whatever main already is, so restricting it to the inputs that change the
        # report is a cost control rather than a way to skip a required context.
        path_filtered_triggers=("push",),
        jobs=(
            (
                "mingw-coverage",
                Job(
                    runner="windows-latest",
                    steps=(
                        CHECKOUT,
                        Step(
                            DISPATCH_IDENTITY_STEP,
                            shell="bash",
                            condition="${{ github.event_name == 'workflow_dispatch' }}",
                            program=DISPATCH_IDENTITY_PROGRAM,
                            environment=DISPATCH_IDENTITY_ENVIRONMENT,
                        ),
                        Step("Add MinGW to PATH", shell="powershell"),
                        Step("Cache pip packages"),
                        Step("Install gcovr", shell="powershell"),
                        Step("Configure (Debug + Tests + Coverage)", shell="bash"),
                        Step("Build", shell="bash"),
                        Step("Copy MinGW runtime DLLs", shell="powershell", program=COVERAGE_RUNTIME_DLL_PROGRAM),
                        Step("Run Tests", shell="bash", program=("ctest --preset mingw-debug",)),
                        Step("Generate HTML Coverage Report", shell="bash"),
                        Step("Setup Pages"),
                        Step("Upload Pages artifact"),
                    ),
                ),
            ),
            (
                "msvc-verify",
                Job(
                    runner="windows-latest",
                    steps=(
                        CHECKOUT,
                        Step("Set up MSVC developer environment"),
                        Step("Configure (MSVC Debug + Tests)", shell="cmd"),
                        Step("Build", shell="cmd"),
                        Step("Run Tests", shell="cmd", program=("ctest --preset msvc-debug",)),
                    ),
                ),
            ),
            (
                "deploy-pages",
                Job(
                    runner="ubuntu-latest",
                    needs=("mingw-coverage", "msvc-verify"),
                    steps=(Step("Deploy to GitHub Pages"),),
                ),
            ),
        ),
    ),
}

# Exact normalized-source identities close the parts of GitHub Actions YAML that the structural reader
# deliberately does not try to interpret: action references and inputs, trigger values, matrices,
# permissions, outputs, defaults, and every unlisted shell line. The checker explicitly normalizes CRLF
# and bare CR to LF, keeping the identity stable across checkouts while every other byte remains significant.
WORKFLOW_SOURCE_SHA256 = {
    ARCH_GATE: "4f307412bc640b90f87f7809f21d961b705de5bf3db7e551d42b8bae1ce66f48",
    COVERAGE_PAGES: "26bdef5ac3ae7f92ce55edee2df9f474b8799cedf740560ccbb8b572b7706def",
    PR_CHECK: "2603b1f617b250f8da4313a106a07ea97c30f43be89e19b2e08d2ccdab149264",
    QUALITY: "2a0c3cef8480b6446f4c3068a0f9675e048581de96152bd008adb158633f54ab",
    RELEASE: "069396585b7b5c686bc8320d3f7c3de3206a8fdea509a5f3e76ce35a1ac452b7",
    SANITIZERS: "7d53176e985a113cd496e59bce3fec5a2585fb15f1deed7928d0b09fd9a55d57",
    SIMD: "8824ad65838c14465826c71c8a3ab5504e050ea43bf8112ccec813cc47b45800",
}
