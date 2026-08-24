/**
 * @file corpus_sighealth.cpp
 * @brief Signature-health corpus report (T-SIGHEALTH-CORPUS): estimate vs ground truth over real x64 code.
 *
 * The sighealth expected-match model multiplies per-position selectivity under an independent-byte assumption. Real x64
 * .text is not independent-byte: canonical MSVC prologues repeat thousands of times, so the model can grade a short
 * prologue pattern far more selective than it is (a false negative for the lint), while a pattern that fixes an operand
 * byte can be unique today and silently volatile across a relink (a hazard the pattern-level model cannot see at all).
 * P1-9 requires this report before any rarity/grade threshold change or any generic prologue/movabs/immediate
 * heuristic: the tool loads a representative corpus of system x64 images plus this executable's own statically linked
 * C++ code, counts ground-truth matches for each probe with a naive masked matcher, and prints estimate-vs-actual per
 * probe.
 *
 * Probe categories:
 *   - canonical-prologue: common MSVC/GCC function prologues and padding, the false-negative cases.
 *   - unmasked-operand:   a RIP-relative load with its disp32 fixed from a live corpus site (unique today,
 *                         volatile tomorrow) against its properly wildcarded form.
 *   - synthetic-unique:   a movabs with an invented imm64, the true-unique control.
 *   - wildcard:           a wildcard-heavy shape, the over-warn (false-positive) direction.
 *
 * Build with -DDMK_BUILD_BENCHMARKS=ON. Executable: DetourModKit_corpus_sighealth. Output: a per-probe table, #TSV
 * rows, and the gate records described in bench_gate.hpp.
 */

#include "DetourModKit/scan.hpp"
#include "DetourModKit/sighealth.hpp"

#include "bench_gate.hpp"

#include <windows.h>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace
{
    namespace sighealth = DetourModKit::sighealth;
    using DetourModKit::scan::Pattern;

    struct CorpusModule
    {
        std::string name;
        std::vector<std::uint8_t> text;
    };

    /// Copies every executable section of a loaded image. Returns an empty vector when the image is absent.
    std::vector<std::uint8_t> executable_bytes(HMODULE module)
    {
        std::vector<std::uint8_t> text;
        if (module == nullptr)
        {
            return text;
        }
        const auto *base = reinterpret_cast<const std::uint8_t *>(module);
        const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return text;
        }
        const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return text;
        }
        const IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section->Misc.VirtualSize == 0)
            {
                continue;
            }
            const std::uint8_t *begin = base + section->VirtualAddress;
            text.insert(text.end(), begin, begin + section->Misc.VirtualSize);
        }
        return text;
    }

    /// Ground truth: naive masked match count. The scan engine is the finder; this loop is the oracle.
    std::size_t count_matches(const Pattern &pattern, const std::vector<std::uint8_t> &haystack)
    {
        const std::span<const std::byte> bytes = pattern.bytes();
        const std::span<const std::byte> masks = pattern.mask();
        const std::size_t length = pattern.size();
        if (length == 0 || haystack.size() < length)
        {
            return 0;
        }
        std::size_t matches = 0;
        const std::size_t last = haystack.size() - length;
        for (std::size_t offset = 0; offset <= last; ++offset)
        {
            bool hit = true;
            for (std::size_t j = 0; j < length; ++j)
            {
                const auto mask = static_cast<std::uint8_t>(masks[j]);
                if ((haystack[offset + j] & mask) != (static_cast<std::uint8_t>(bytes[j]) & mask))
                {
                    hit = false;
                    break;
                }
            }
            matches += hit ? 1u : 0u;
        }
        return matches;
    }

    struct Probe
    {
        const char *name;
        const char *category;
        std::string dsl;
    };
} // namespace

int main()
{
    dmk_bench::GateLedger gates("corpus");

    // The corpus: OS loader/Win32/CRT images every x64 Windows host maps, plus this executable's own image,
    // whose .text is statically linked DMK + CRT C++ (the game-modding target shape).
    const wchar_t *module_names[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"user32.dll",
        L"gdi32.dll",
        L"gdi32full.dll",
        L"msvcrt.dll",
        L"ucrtbase.dll",
        L"ole32.dll",
        L"combase.dll",
        L"rpcrt4.dll",
        L"advapi32.dll",
        L"oleaut32.dll",
        L"setupapi.dll",
        L"shell32.dll",
        L"d3d11.dll",
        L"dwrite.dll",
        L"windows.storage.dll"
    };
    std::vector<CorpusModule> corpus;
    for (const wchar_t *name : module_names)
    {
        HMODULE module = GetModuleHandleW(name);
        if (module == nullptr)
        {
            module = LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        std::vector<std::uint8_t> text = executable_bytes(module);
        if (!text.empty())
        {
            char narrow[64]{};
            std::snprintf(narrow, sizeof(narrow), "%ls", name);
            corpus.push_back({narrow, std::move(text)});
        }
    }
    corpus.push_back({"self(.exe, static DMK)", executable_bytes(GetModuleHandleW(nullptr))});

    std::uint64_t corpus_bytes = 0;
    for (const CorpusModule &module : corpus)
    {
        corpus_bytes += module.text.size();
    }
    gates.fact("corpus.modules_loaded_at_least_8", corpus.size() >= 8);
    gates.fact("corpus.corpus_at_least_16mib", corpus_bytes >= (16ull << 20));
    std::printf(
        "Signature-health corpus: %zu modules, %.1f MiB of x64 executable bytes\n",
        corpus.size(),
        static_cast<double>(corpus_bytes) / (1024.0 * 1024.0)
    );
    for (const CorpusModule &module : corpus)
    {
        std::printf("  %-24s %9zu bytes\n", module.name.c_str(), module.text.size());
    }

    // Locate a live RIP-relative load and freeze its actual disp32 into the fixed-operand probe, so the
    // "unique today, volatile tomorrow" case is built from a real site rather than an invented one.
    std::string fixed_rip_dsl;
    {
        const auto compiled = Pattern::compile("48 8B 05 ?? ?? ?? ??");
        if (compiled)
        {
            for (const CorpusModule &module : corpus)
            {
                const std::span<const std::byte> bytes = compiled->bytes();
                const std::span<const std::byte> masks = compiled->mask();
                const std::size_t length = compiled->size();
                for (std::size_t offset = 0; offset + length <= module.text.size(); ++offset)
                {
                    bool hit = true;
                    for (std::size_t j = 0; j < length; ++j)
                    {
                        const auto mask = static_cast<std::uint8_t>(masks[j]);
                        if ((module.text[offset + j] & mask) != (static_cast<std::uint8_t>(bytes[j]) & mask))
                        {
                            hit = false;
                            break;
                        }
                    }
                    if (hit)
                    {
                        char dsl[64];
                        std::snprintf(
                            dsl,
                            sizeof(dsl),
                            "48 8B 05 %02X %02X %02X %02X",
                            module.text[offset + 3],
                            module.text[offset + 4],
                            module.text[offset + 5],
                            module.text[offset + 6]
                        );
                        fixed_rip_dsl = dsl;
                        break;
                    }
                }
                if (!fixed_rip_dsl.empty())
                {
                    break;
                }
            }
        }
    }
    gates.fact("corpus.fixed_operand_site_found", !fixed_rip_dsl.empty());
    if (fixed_rip_dsl.empty())
    {
        return gates.close();
    }

    const Probe probes[] = {
        {"prologue_push_sub", "canonical-prologue", "40 53 48 83 EC 20"},
        {"prologue_spill", "canonical-prologue", "48 89 5C 24 08"},
        {"prologue_spill_long", "canonical-prologue", "48 89 5C 24 08 48 89 74 24 10 57"},
        {"prologue_sub_only", "canonical-prologue", "48 83 EC 28"},
        {"int3_padding", "canonical-prologue", "CC CC CC CC CC CC CC CC"},
        {"rip_load_masked", "unmasked-operand", "48 8B 05 ?? ?? ?? ??"},
        {"rip_load_fixed_disp", "unmasked-operand", fixed_rip_dsl},
        {"movabs_synthetic_imm", "synthetic-unique", "48 B8 13 57 9B DF 24 68 AC E1"},
        {"wildcard_heavy", "wildcard", "48 ?? ?? ?? 24 ?? ?? 89"},
    };

    std::printf(
        "\n%-22s %-18s %4s %-8s %12s %14s %10s\n",
        "probe",
        "category",
        "len",
        "grade",
        "est/64MiB",
        "actual/64MiB",
        "raw hits"
    );
    bool all_compiled = true;
    double prologue_actual_per_64mib = 0.0;
    double prologue_estimate_per_64mib = 0.0;
    std::size_t synthetic_hits = 0;
    std::size_t fixed_rip_hits = 0;
    const double scale_to_64mib = static_cast<double>(64ull << 20) / static_cast<double>(corpus_bytes);
    for (const Probe &probe : probes)
    {
        const auto compiled = Pattern::compile(probe.dsl);
        if (!compiled)
        {
            all_compiled = false;
            std::printf("%-22s %-18s COMPILE FAILED\n", probe.name, probe.category);
            continue;
        }
        const sighealth::PatternHealth health = sighealth::analyze_pattern(*compiled);
        std::size_t hits = 0;
        for (const CorpusModule &module : corpus)
        {
            hits += count_matches(*compiled, module.text);
        }
        const double actual_per_64mib = static_cast<double>(hits) * scale_to_64mib;
        std::printf(
            "%-22s %-18s %4zu %-8s %12.3f %14.1f %10zu\n",
            probe.name,
            probe.category,
            compiled->size(),
            std::string(sighealth::to_string(health.grade)).c_str(),
            health.expected_matches,
            actual_per_64mib,
            hits
        );
        std::printf(
            "#TSV\t%s\testimate\t%.4f\tactual_per_64mib\t%.2f\traw\t%zu\tgrade\t%s\n",
            probe.name,
            health.expected_matches,
            actual_per_64mib,
            hits,
            std::string(sighealth::to_string(health.grade)).c_str()
        );
        if (std::strcmp(probe.name, "prologue_push_sub") == 0)
        {
            prologue_actual_per_64mib = actual_per_64mib;
            prologue_estimate_per_64mib = health.expected_matches;
        }
        if (std::strcmp(probe.name, "movabs_synthetic_imm") == 0)
        {
            synthetic_hits = hits;
        }
        if (std::strcmp(probe.name, "rip_load_fixed_disp") == 0)
        {
            fixed_rip_hits = hits;
        }
    }
    gates.fact("corpus.all_probes_compile", all_compiled);

    // Deterministic corpus facts: canonical prologues are common in ANY real x64 Windows image set (the false-negative
    // direction the report documents), a 10-byte invented immediate matches nothing, and the frozen-disp site matches
    // at least its own occurrence.
    gates.fact(
        "corpus.canonical_prologue_exceeds_fail_threshold",
        prologue_actual_per_64mib > sighealth::HealthPolicy{}.fail_expected_matches
    );
    gates.fact("corpus.synthetic_unique_absent", synthetic_hits == 0);
    gates.fact("corpus.fixed_operand_site_matches", fixed_rip_hits >= 1);

    // The headline metric: how far the independent-byte model underestimates a canonical prologue. The
    // divisor floor keeps a sub-epsilon estimate from turning the ratio into an unrepresentable value.
    const double underestimate_ratio =
        prologue_actual_per_64mib / (prologue_estimate_per_64mib > 0.001 ? prologue_estimate_per_64mib : 0.001);
    gates.metric("corpus.prologue_underestimate_ratio", underestimate_ratio);
    gates.metric("corpus.corpus_bytes", static_cast<double>(corpus_bytes));
    std::printf(
        "\nprologue_push_sub underestimate: model %.3f vs actual %.1f per 64 MiB (%.0fx)\n",
        prologue_estimate_per_64mib,
        prologue_actual_per_64mib,
        underestimate_ratio
    );
    return gates.close();
}
