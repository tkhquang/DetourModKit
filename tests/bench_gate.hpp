#ifndef DETOURMODKIT_TESTS_BENCH_GATE_HPP
#define DETOURMODKIT_TESTS_BENCH_GATE_HPP

/**
 * @file bench_gate.hpp
 * @brief The machine-checkable gate record every benchmark executable emits.
 * @details A benchmark is release evidence only when a failure inside it is visible to whatever ran it. Each
 *          executable records one `#GATE` line per checked property and one terminal `#GATE-END` line, then exits
 *          nonzero if any deterministic gate failed. The sentinel is what separates "nothing failed" from "the run
 *          died before reaching the check": a parser that only reads the lines present cannot otherwise tell a clean
 *          suite from a truncated one.
 *
 *          Deterministic gates are correctness facts (a pattern compiled, a page committed, a sample count reached)
 *          and block on any host. Timing gates carry a declared wall-clock ratio, are recorded everywhere, and are
 *          enforced only where scripts/check_benchmark_results.py is told the host is stable, because a shared runner
 *          cannot distinguish a regression from a noisy neighbour.
 *
 *          One definition rather than one per benchmark: four copies of the format would drift, and a drifted record
 *          is exactly what the parser cannot catch.
 *
 *          Every record is identified by a (suite, name) pair, and the name is qualified with its own suite. The
 *          ledger refuses to emit a record that breaks that shape, because an empty or foreign-qualified identity is
 *          not a record a `--require` list can bind to: the checker would be asserting the presence of something no
 *          suite owns.
 */

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace dmk_bench
{
    /// Whether a gate blocks on any host or only where the checker is told the host is stable.
    enum class GateKind : unsigned char
    {
        Deterministic,
        Timing
    };

    /**
     * @brief Accumulates one benchmark's gate records and decides its exit status.
     * @details Each record prints as it is added, so a suite that dies mid-run still shows what it had proved and the
     *          absent sentinel fails the parser. Every member is usable from a benchmark's noexcept setup helpers.
     */
    class GateLedger
    {
    public:
        explicit GateLedger(const char *suite) noexcept
            : m_suite(suite != nullptr ? suite : ""),
              m_suite_valid(suite != nullptr && suite[0] != '\0' && std::strchr(suite, '.') == nullptr)
        {
            if (!m_suite_valid)
            {
                ++m_refusals;
                std::fprintf(
                    stderr,
                    "bench_gate: refusing suite '%s': suite must be nonempty and contain no '.'\n",
                    suite != nullptr ? suite : "(null)"
                );
                (void)std::fflush(stderr);
            }
        }

        /// Records a correctness fact that blocks on every host.
        void fact(const char *name, bool passed) noexcept
        {
            emit(name, GateKind::Deterministic, passed, passed ? 1.0 : 0.0, ">=", 1.0);
        }

        /// Records a wall-clock ratio required to stay at or above @p threshold.
        void at_least(const char *name, double observed, double threshold) noexcept
        {
            emit(name, GateKind::Timing, observed >= threshold, observed, ">=", threshold);
        }

        /// Records a wall-clock ratio required to stay at or below @p threshold.
        void at_most(const char *name, double observed, double threshold) noexcept
        {
            emit(name, GateKind::Timing, observed <= threshold, observed, "<=", threshold);
        }

        /**
         * @brief Records a measured value whose policy needs more than one run to decide.
         * @details A tier-versus-tier throughput ratio is a comparison between two builds, so a single run cannot
         *          gate it without inventing a threshold. The value is published here and the checker enforces the
         *          declared ratio against a baseline run, on a stable host only.
         */
        void metric(const char *name, double value) noexcept
        {
            require_open("record a metric");
            if (!identifies(name))
            {
                return;
            }
            std::printf("#METRIC\t%s\t%s\t%.6f\n", m_suite, name, value);
        }

        /**
         * @brief Records a failed setup fact, closes the record set, and exits.
         * @details For the setup failures a suite cannot continue past. Closing first keeps the sentinel present, so
         *          the parser reports the named failed gate rather than a truncated run.
         */
        [[noreturn]] void abort_setup(const char *name) noexcept
        {
            fact(name, false);
            std::exit(close());
        }

        /// Closes the record set and returns the exit status: nonzero after a failed gate or any refusal.
        [[nodiscard]] int close() noexcept
        {
            if (m_closed)
            {
                report_closed("close it again");
                return EXIT_FAILURE;
            }
            m_closed = true;
            if (m_suite_valid && m_count == 0)
            {
                ++m_refusals;
                std::fprintf(stderr, "bench_gate: refusing suite '%s': suite must emit at least one gate\n", m_suite);
                (void)std::fflush(stderr);
            }
            if (m_suite_valid)
            {
                std::printf("#GATE-END\t%s\t%d\n", m_suite, m_count);
            }
            (void)std::fflush(stdout);
            return m_deterministic_failures == 0 && m_refusals == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }

    private:
        /**
         * @brief Whether @p name is a nonempty identity qualified with this ledger's nonempty suite.
         * @details A refusal is counted and reported on stderr rather than emitted, so the record is absent (which
         *          fails any `--require` naming it) and the process exit status is nonzero on its own.
         */
        [[nodiscard]] bool identifies(const char *name) noexcept
        {
            if (!m_suite_valid)
            {
                return false;
            }
            const std::size_t suite_length = std::strlen(m_suite);
            if (name != nullptr && std::strncmp(name, m_suite, suite_length) == 0 && name[suite_length] == '.' &&
                name[suite_length + 1] != '\0')
            {
                return true;
            }
            ++m_refusals;
            std::fprintf(
                stderr,
                "bench_gate: refusing record '%s' in suite '%s': a record name must be the suite followed "
                "by '.' and a nonempty remainder\n",
                name != nullptr ? name : "(null)",
                m_suite
            );
            (void)std::fflush(stderr);
            return false;
        }

        void report_closed(const char *action) const noexcept
        {
            std::fprintf(
                stderr,
                "bench_gate: ledger for suite '%s' is already closed; refusing to %s\n",
                m_suite,
                action
            );
            (void)std::fflush(stderr);
        }

        void require_open(const char *action) const noexcept
        {
            if (!m_closed)
            {
                return;
            }
            report_closed(action);
            std::exit(EXIT_FAILURE);
        }

        void emit(
            const char *name,
            GateKind kind,
            bool passed,
            double observed,
            const char *relation,
            double threshold
        ) noexcept
        {
            require_open("record a gate");
            if (!identifies(name))
            {
                return;
            }
            ++m_count;
            if (!passed && kind == GateKind::Deterministic)
            {
                ++m_deterministic_failures;
            }
            std::printf(
                "#GATE\t%s\t%s\t%s\t%s\t%.6f\t%s\t%.6f\n",
                m_suite,
                name,
                kind == GateKind::Deterministic ? "deterministic" : "timing",
                passed ? "pass" : "fail",
                observed,
                relation,
                threshold
            );
        }

        const char *m_suite;
        bool m_suite_valid;
        bool m_closed{false};
        int m_count{0};
        int m_deterministic_failures{0};
        int m_refusals{0};
    };
} // namespace dmk_bench

#if defined(DMK_BENCH_GATE_PROBE_MAIN)

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: dmk_bench_gate_probe MODE\n");
        return 2;
    }

    const char *mode = argv[1];
    if (std::strcmp(mode, "null_suite") == 0)
    {
        dmk_bench::GateLedger gates(nullptr);
        return gates.close();
    }
    if (std::strcmp(mode, "empty_suite") == 0)
    {
        dmk_bench::GateLedger gates("");
        return gates.close();
    }
    if (std::strcmp(mode, "dotted_suite") == 0)
    {
        dmk_bench::GateLedger gates("scanner.verify");
        gates.fact("scanner.verify.control", true);
        return gates.close();
    }

    dmk_bench::GateLedger gates("scanner");
    if (std::strcmp(mode, "zero_records") == 0)
    {
        return gates.close();
    }
    if (std::strcmp(mode, "metric_only") == 0)
    {
        gates.metric("scanner.value", 2.0);
        return gates.close();
    }
    if (std::strcmp(mode, "deterministic_fail") == 0)
    {
        gates.fact("scanner.control", false);
        return gates.close();
    }
    if (std::strcmp(mode, "timing_fail") == 0)
    {
        gates.at_least("scanner.control", 0.5, 1.0);
        return gates.close();
    }

    gates.fact("scanner.control", true);
    if (std::strcmp(mode, "valid") == 0)
    {
        gates.metric("scanner.value", 2.0);
        return gates.close();
    }
    if (std::strcmp(mode, "null_gate") == 0)
    {
        gates.fact(nullptr, true);
    }
    else if (std::strcmp(mode, "empty_gate") == 0)
    {
        gates.fact("", true);
    }
    else if (std::strcmp(mode, "unqualified_gate") == 0)
    {
        gates.fact("control", true);
    }
    else if (std::strcmp(mode, "bare_gate") == 0)
    {
        gates.fact("scanner.", true);
    }
    else if (std::strcmp(mode, "foreign_gate") == 0)
    {
        gates.fact("memory.control", true);
    }
    else if (std::strcmp(mode, "null_metric") == 0)
    {
        gates.metric(nullptr, 2.0);
    }
    else if (std::strcmp(mode, "empty_metric") == 0)
    {
        gates.metric("", 2.0);
    }
    else if (std::strcmp(mode, "unqualified_metric") == 0)
    {
        gates.metric("value", 2.0);
    }
    else if (std::strcmp(mode, "bare_metric") == 0)
    {
        gates.metric("scanner.", 2.0);
    }
    else if (std::strcmp(mode, "foreign_metric") == 0)
    {
        gates.metric("memory.value", 2.0);
    }
    else if (std::strcmp(mode, "double_close") == 0)
    {
        const int first_status = gates.close();
        if (first_status != EXIT_SUCCESS)
        {
            return first_status;
        }
        return gates.close();
    }
    else if (std::strcmp(mode, "gate_after_close") == 0)
    {
        if (gates.close() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
        gates.fact("scanner.late", true);
        return EXIT_SUCCESS;
    }
    else if (std::strcmp(mode, "metric_after_close") == 0)
    {
        if (gates.close() != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
        gates.metric("scanner.late", 2.0);
        return EXIT_SUCCESS;
    }
    else
    {
        std::fprintf(stderr, "unknown probe mode: %s\n", mode);
        return 2;
    }
    return gates.close();
}

#endif

#endif // DETOURMODKIT_TESTS_BENCH_GATE_HPP
