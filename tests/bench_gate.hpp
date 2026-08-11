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
 */

#include <cstdio>
#include <cstdlib>

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
        explicit GateLedger(const char *suite) noexcept : m_suite(suite) {}

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

        /// Closes the record set and returns the process exit status: nonzero when a deterministic gate failed.
        [[nodiscard]] int close() noexcept
        {
            std::printf("#GATE-END\t%s\t%d\n", m_suite, m_count);
            (void)std::fflush(stdout);
            return m_deterministic_failures == 0 ? 0 : 1;
        }

    private:
        void emit(const char *name, GateKind kind, bool passed, double observed, const char *relation,
                  double threshold) noexcept
        {
            ++m_count;
            if (!passed && kind == GateKind::Deterministic)
            {
                ++m_deterministic_failures;
            }
            std::printf("#GATE\t%s\t%s\t%s\t%s\t%.6f\t%s\t%.6f\n", m_suite, name,
                        kind == GateKind::Deterministic ? "deterministic" : "timing", passed ? "pass" : "fail",
                        observed, relation, threshold);
        }

        const char *m_suite;
        int m_count{0};
        int m_deterministic_failures{0};
    };
} // namespace dmk_bench

#endif // DETOURMODKIT_TESTS_BENCH_GATE_HPP
