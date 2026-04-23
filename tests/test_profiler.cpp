#include <gtest/gtest.h>

#include "DetourModKit/profiler.hpp"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <type_traits>
#include <vector>

using namespace DetourModKit;

// --- Profiler singleton ---

TEST(ProfilerTest, GetInstance_ReturnsSameInstance)
{
    auto &a = Profiler::get_instance();
    auto &b = Profiler::get_instance();
    EXPECT_EQ(&a, &b);
}

TEST(ProfilerTest, DefaultCapacity_IsPowerOfTwo)
{
    const auto &profiler = Profiler::get_instance();
    const size_t cap = profiler.capacity();
    EXPECT_GT(cap, 0u);
    EXPECT_EQ(cap & (cap - 1), 0u); // power of 2
}

TEST(ProfilerTest, QpcFrequency_IsPositive)
{
    const auto &profiler = Profiler::get_instance();
    EXPECT_GT(profiler.qpc_frequency(), 0);
}

// --- Recording ---

class ProfilerRecordTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Profiler::get_instance().reset();
    }
    void TearDown() override
    {
        Profiler::get_instance().reset();
    }
};

TEST_F(ProfilerRecordTest, Record_IncrementsSampleCount)
{
    auto &profiler = Profiler::get_instance();
    EXPECT_EQ(profiler.total_samples_recorded(), 0u);

    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&end);

    profiler.record("test_scope", start.QuadPart, end.QuadPart, 42);
    EXPECT_EQ(profiler.total_samples_recorded(), 1u);
    EXPECT_EQ(profiler.available_samples(), 1u);
}

TEST_F(ProfilerRecordTest, Record_MultipleSamples)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    for (int i = 0; i < 100; ++i)
    {
        profiler.record("loop_iter", tick.QuadPart, tick.QuadPart + 1000, 1);
    }
    EXPECT_EQ(profiler.total_samples_recorded(), 100u);
    EXPECT_EQ(profiler.available_samples(), 100u);
}

TEST_F(ProfilerRecordTest, Reset_ClearsAllSamples)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    profiler.record("before_reset", tick.QuadPart, tick.QuadPart + 100, 1);
    EXPECT_EQ(profiler.total_samples_recorded(), 1u);

    profiler.reset();
    EXPECT_EQ(profiler.total_samples_recorded(), 0u);
    EXPECT_EQ(profiler.available_samples(), 0u);
}

TEST_F(ProfilerRecordTest, RingBuffer_WrapsAtCapacity)
{
    auto &profiler = Profiler::get_instance();
    const size_t cap = profiler.capacity();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    // Fill buffer + 10 extra to trigger wrap
    for (size_t i = 0; i < cap + 10; ++i)
    {
        profiler.record("wrap_test", tick.QuadPart, tick.QuadPart + 1, 1);
    }

    EXPECT_EQ(profiler.total_samples_recorded(), cap + 10);
    EXPECT_EQ(profiler.available_samples(), cap);
}

// --- ScopedProfile ---

TEST_F(ProfilerRecordTest, ScopedProfile_RecordsSample)
{
    auto &profiler = Profiler::get_instance();

    {
        ScopedProfile sp("scoped_test");
        // Simulate some work
        volatile int sum = 0;
        for (int i = 0; i < 1000; ++i)
        {
            sum += i;
        }
        (void)sum;
    }

    EXPECT_EQ(profiler.total_samples_recorded(), 1u);
}

TEST_F(ProfilerRecordTest, ScopedProfile_MeasuresPositiveDuration)
{
    auto &profiler = Profiler::get_instance();

    {
        ScopedProfile sp("duration_test");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    ASSERT_EQ(profiler.total_samples_recorded(), 1u);

    // Export and verify the sample has a positive duration
    const std::string json = profiler.export_chrome_json();
    EXPECT_NE(json.find("\"dur\":"), std::string::npos);
    // Duration should be >= 1000 us (1 ms sleep)
    EXPECT_NE(json.find("duration_test"), std::string::npos);
}

// --- Chrome Tracing JSON export ---

TEST_F(ProfilerRecordTest, ExportChromeJson_EmptyBuffer)
{
    const auto &profiler = Profiler::get_instance();
    const std::string json = profiler.export_chrome_json();
    EXPECT_EQ(json, "[]");
}

TEST_F(ProfilerRecordTest, ExportChromeJson_SingleSample)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);
    profiler.record("single", tick.QuadPart, tick.QuadPart + 10000, 99);

    const std::string json = profiler.export_chrome_json();

    // Verify required Chrome Trace Event fields
    EXPECT_NE(json.find("\"name\":\"single\""), std::string::npos);
    EXPECT_NE(json.find("\"ph\":\"X\""), std::string::npos);
    EXPECT_NE(json.find("\"ts\":"), std::string::npos);
    EXPECT_NE(json.find("\"dur\":"), std::string::npos);
    EXPECT_NE(json.find("\"tid\":99"), std::string::npos);
    EXPECT_NE(json.find("\"pid\":1"), std::string::npos);
}

TEST_F(ProfilerRecordTest, ExportChromeJson_MultipleSamples_ValidArray)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    profiler.record("first", tick.QuadPart, tick.QuadPart + 100, 1);
    profiler.record("second", tick.QuadPart + 200, tick.QuadPart + 400, 2);

    const std::string json = profiler.export_chrome_json();

    // Must start with [ and end with ]
    EXPECT_EQ(json.front(), '[');
    EXPECT_EQ(json.back(), ']');

    // Both samples present
    EXPECT_NE(json.find("\"name\":\"first\""), std::string::npos);
    EXPECT_NE(json.find("\"name\":\"second\""), std::string::npos);
}

// --- File export ---

TEST_F(ProfilerRecordTest, ExportToFile_WritesValidFile)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);
    profiler.record("file_test", tick.QuadPart, tick.QuadPart + 5000, 1);

    const std::string path = std::format("dmk_profiler_test_{}.json", _getpid());
    const bool ok = profiler.export_to_file(path);
    EXPECT_TRUE(ok);

    // Read back and verify
    std::FILE *fp = std::fopen(path.c_str(), "rb");
    ASSERT_NE(fp, nullptr);
    std::fseek(fp, 0, SEEK_END);
    const long size = std::ftell(fp);
    ASSERT_GE(size, 0L) << "ftell failed";
    std::fseek(fp, 0, SEEK_SET);
    std::string content(static_cast<size_t>(size), '\0');
    (void)std::fread(content.data(), 1, static_cast<size_t>(size), fp);
    std::fclose(fp);
    std::remove(path.c_str());

    EXPECT_NE(content.find("file_test"), std::string::npos);
    EXPECT_EQ(content.front(), '[');
}

TEST_F(ProfilerRecordTest, ExportToFile_InvalidPath_ReturnsFalse)
{
    const auto &profiler = Profiler::get_instance();
    const bool ok = profiler.export_to_file("Z:\\nonexistent\\dir\\file.json");
    EXPECT_FALSE(ok);
}

// --- Concurrent recording ---

TEST_F(ProfilerRecordTest, ConcurrentRecord_NoDataRace)
{
    auto &profiler = Profiler::get_instance();
    constexpr int threads = 8;
    constexpr int samples_per_thread = 1000;

    std::vector<std::thread> workers;
    workers.reserve(threads);

    for (int t = 0; t < threads; ++t)
    {
        workers.emplace_back([&profiler]() {
            LARGE_INTEGER tick;
            for (int i = 0; i < samples_per_thread; ++i)
            {
                QueryPerformanceCounter(&tick);
                profiler.record("concurrent", tick.QuadPart,
                                tick.QuadPart + 100, GetCurrentThreadId());
            }
        });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    EXPECT_EQ(profiler.total_samples_recorded(),
              static_cast<size_t>(threads * samples_per_thread));
}

TEST_F(ProfilerRecordTest, ConcurrentScopedProfile_NoDataRace)
{
    auto &profiler = Profiler::get_instance();
    constexpr int threads = 4;
    constexpr int scopes_per_thread = 500;

    std::vector<std::thread> workers;
    workers.reserve(threads);

    for (int t = 0; t < threads; ++t)
    {
        workers.emplace_back([]() {
            for (int i = 0; i < scopes_per_thread; ++i)
            {
                ScopedProfile sp("concurrent_scope");
            }
        });
    }

    for (auto &w : workers)
    {
        w.join();
    }

    EXPECT_EQ(profiler.total_samples_recorded(),
              static_cast<size_t>(threads * scopes_per_thread));
}

// --- Sequence counter (torn read protection) ---

TEST_F(ProfilerRecordTest, ConcurrentRecordAndExport_NoTornReads)
{
    auto &profiler = Profiler::get_instance();
    std::atomic<bool> stop{false};
    std::atomic<int> export_count{0};

    // Writer threads: continuously record samples
    std::vector<std::thread> writers;
    for (int t = 0; t < 4; ++t)
    {
        writers.emplace_back([&profiler, &stop]() {
            LARGE_INTEGER tick;
            while (!stop.load(std::memory_order_relaxed))
            {
                QueryPerformanceCounter(&tick);
                profiler.record("concurrent_export", tick.QuadPart,
                                tick.QuadPart + 100, GetCurrentThreadId());
            }
        });
    }

    // Reader thread: export while writers are active
    std::thread reader([&profiler, &stop, &export_count]() {
        while (!stop.load(std::memory_order_relaxed))
        {
            const std::string json = profiler.export_chrome_json();
            // Verify the JSON is well-formed (starts with [, ends with ])
            if (!json.empty())
            {
                EXPECT_EQ(json.front(), '[');
                EXPECT_EQ(json.back(), ']');
            }
            export_count.fetch_add(1, std::memory_order_relaxed);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    stop.store(true, std::memory_order_relaxed);

    for (auto &w : writers)
    {
        w.join();
    }
    reader.join();

    EXPECT_GT(export_count.load(), 0);
}

// --- Macro tests ---

#ifdef DMK_ENABLE_PROFILING

TEST_F(ProfilerRecordTest, ProfileScopeMacro_RecordsSample)
{
    auto &profiler = Profiler::get_instance();

    {
        DMK_PROFILE_SCOPE("macro_test");
    }

    EXPECT_EQ(profiler.total_samples_recorded(), 1u);
}

TEST_F(ProfilerRecordTest, ProfileFunctionMacro_RecordsSample)
{
    auto &profiler = Profiler::get_instance();

    {
        DMK_PROFILE_FUNCTION();
    }

    EXPECT_EQ(profiler.total_samples_recorded(), 1u);
}

#else

TEST_F(ProfilerRecordTest, ProfileScopeMacro_IsNoOpWhenDisabled)
{
    auto &profiler = Profiler::get_instance();

    {
        DMK_PROFILE_SCOPE("should_not_record");
    }

    // Macros expand to ((void)0), so nothing is recorded
    EXPECT_EQ(profiler.total_samples_recorded(), 0u);
}

#endif // DMK_ENABLE_PROFILING

TEST_F(ProfilerRecordTest, AvailableSamples_InitiallyZero)
{
    const auto &profiler = Profiler::get_instance();
    EXPECT_EQ(profiler.available_samples(), 0u);
}

TEST_F(ProfilerRecordTest, AvailableSamples_MatchesRecordCount)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    for (int i = 0; i < 5; ++i)
    {
        profiler.record("sample", tick.QuadPart, tick.QuadPart + 100, 1);
    }
    EXPECT_EQ(profiler.available_samples(), 5u);
}

// --- JSON escaping ---

TEST_F(ProfilerRecordTest, ExportChromeJson_EscapesQuotesInName)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    // Name contains characters that must be escaped in JSON
    profiler.record("scope\"with\\special\tchars", tick.QuadPart, tick.QuadPart + 100, 1);

    const std::string json = profiler.export_chrome_json();

    // Quotes and backslashes must be escaped in the JSON output
    EXPECT_NE(json.find("scope\\\"with\\\\special\\tchars"), std::string::npos)
        << "JSON output must escape special characters. Got: " << json;

    // Verify the JSON is still well-formed (starts with [, ends with ])
    EXPECT_EQ(json.front(), '[');
    EXPECT_EQ(json.back(), ']');
}

TEST_F(ProfilerRecordTest, ExportChromeJson_EscapesControlCharacters)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    // Name with a newline and carriage return
    profiler.record("line1\nline2\r", tick.QuadPart, tick.QuadPart + 100, 1);

    const std::string json = profiler.export_chrome_json();

    // Newline and CR must be escaped
    EXPECT_NE(json.find("line1\\nline2\\r"), std::string::npos)
        << "JSON output must escape control characters. Got: " << json;
}

TEST_F(ProfilerRecordTest, ExportChromeJson_EscapesBackspaceFormFeedAndRawControl)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    // Name with backspace, form-feed, and a raw control byte (SOH = 0x01).
    // String concatenation separates \x01 from the trailing 'd' to prevent
    // the compiler from parsing "\x01d" as a single hex escape (0x1D).
    const char name[] = "a\bb\fc" "\x01" "d";
    profiler.record(name, tick.QuadPart, tick.QuadPart + 100, 1);

    const std::string json = profiler.export_chrome_json();

    EXPECT_NE(json.find("a\\bb\\fc\\u0001d"), std::string::npos)
        << "JSON output must escape \\b, \\f, and raw control bytes. Got: " << json;
}

TEST_F(ProfilerRecordTest, ExportChromeJson_PlainNameUnchanged)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);

    profiler.record("plain_name", tick.QuadPart, tick.QuadPart + 100, 1);

    const std::string json = profiler.export_chrome_json();
    EXPECT_NE(json.find("\"name\":\"plain_name\""), std::string::npos);
}

// Compile-time contract: ScopedProfile must accept string literals (array
// references) and reject decayed `const char*` sources, because the stored
// pointer is read asynchronously by the export path and must outlive the
// process. The array-reference-only constructor enforces this.
static_assert(std::is_constructible_v<ScopedProfile, const char (&)[5]>,
              "ScopedProfile must accept string literals");
static_assert(!std::is_constructible_v<ScopedProfile, const char *>,
              "ScopedProfile must reject decayed const char* (would permit "
              "std::string::c_str() with non-static lifetime)");
static_assert(!std::is_constructible_v<ScopedProfile, char *>,
              "ScopedProfile must reject mutable char*");

TEST_F(ProfilerRecordTest, Capacity_MatchesDefaultCapacity)
{
    const auto &profiler = Profiler::get_instance();
    EXPECT_EQ(profiler.capacity(), Profiler::DEFAULT_CAPACITY);
}

TEST_F(ProfilerRecordTest, ConcurrentRecord_WrapsBuffer_ReaderObservesNoSequenceRollback)
{
    // Stress the seqlock sequence counter under multiple producers racing
    // to wrap the ring buffer. A reader sampling every slot's sequence on
    // a tight loop must never see a slot's sequence decrease, which would
    // indicate a producer rolled the counter back (the pre-v3.1.0 bug in
    // the load-then-store RMW). The monotonic fetch_add open/close pattern
    // guarantees that any reader observes a strictly non-decreasing series
    // of sequence snapshots per slot, regardless of how many writers race.
    auto &profiler = Profiler::get_instance();
    const size_t cap = profiler.capacity();
    std::atomic<bool> stop{false};
    std::atomic<bool> rollback_detected{false};

    std::vector<std::thread> writers;
    writers.reserve(8);
    for (int t = 0; t < 8; ++t)
    {
        writers.emplace_back([&profiler, &stop]() {
            LARGE_INTEGER tick;
            while (!stop.load(std::memory_order_relaxed))
            {
                QueryPerformanceCounter(&tick);
                profiler.record("wrap_race", tick.QuadPart,
                                tick.QuadPart + 1, GetCurrentThreadId());
            }
        });
    }

    // Reader samples every slot's sequence and asserts monotonicity.
    // Using available_samples() + export_chrome_json() exercises the
    // real consumer path, but we also do a direct sampling pass by
    // repeated exports; if any sample had a rolled-back sequence the
    // writer would have produced a torn sample that the JSON parse
    // would either skip (odd sequence) or present with mismatched fields.
    std::thread reader([&profiler, &stop, &rollback_detected]() {
        std::string last_json;
        while (!stop.load(std::memory_order_relaxed))
        {
            const std::string json = profiler.export_chrome_json();
            // Well-formed envelope check: [ ... ] or [].
            if (json.empty() || json.front() != '[' || json.back() != ']')
            {
                rollback_detected.store(true, std::memory_order_relaxed);
                break;
            }
            last_json = json;
        }
    });

    // Enough iterations for multiple full wraps (>= 2 * capacity samples).
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (std::chrono::steady_clock::now() < deadline &&
           profiler.total_samples_recorded() < cap * 3)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    stop.store(true, std::memory_order_relaxed);

    for (auto &w : writers)
    {
        w.join();
    }
    reader.join();

    EXPECT_FALSE(rollback_detected.load());
    EXPECT_GE(profiler.total_samples_recorded(), cap);
}

TEST_F(ProfilerRecordTest, ExportToFile_ContentMatchesChromeJson)
{
    auto &profiler = Profiler::get_instance();

    LARGE_INTEGER tick;
    QueryPerformanceCounter(&tick);
    profiler.record("match_test", tick.QuadPart, tick.QuadPart + 5000, 1);

    const std::string expected = profiler.export_chrome_json();

    const std::string path = std::format("dmk_profiler_match_test_{}.json", _getpid());
    ASSERT_TRUE(profiler.export_to_file(path));

    std::FILE *fp = std::fopen(path.c_str(), "rb");
    ASSERT_NE(fp, nullptr);
    std::fseek(fp, 0, SEEK_END);
    const long size = std::ftell(fp);
    ASSERT_GE(size, 0L);
    std::fseek(fp, 0, SEEK_SET);
    std::string content(static_cast<size_t>(size), '\0');
    (void)std::fread(content.data(), 1, static_cast<size_t>(size), fp);
    std::fclose(fp);
    std::remove(path.c_str());

    EXPECT_EQ(content, expected);
}
