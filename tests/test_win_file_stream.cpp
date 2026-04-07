#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <windows.h>

#include "DetourModKit/win_file_stream.hpp"

using namespace DetourModKit;

class WinFileStreamBufTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_counter = 0;
        test_dir_ = std::filesystem::temp_directory_path() / "dmk_wfs_test";
        std::filesystem::create_directories(test_dir_);
        test_path_ = test_dir_ / ("wfs_" + std::to_string(GetCurrentProcessId()) +
                                  "_" + std::to_string(s_counter++) + ".txt");
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::string read_file(const std::filesystem::path &path)
    {
        std::ifstream in(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    std::filesystem::path test_dir_;
    std::filesystem::path test_path_;
};

// --- WinFileStreamBuf tests ---

TEST_F(WinFileStreamBufTest, DefaultConstruct_NotOpen)
{
    WinFileStreamBuf buf;
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_NarrowPath_Success)
{
    WinFileStreamBuf buf;
    EXPECT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
    EXPECT_TRUE(buf.is_open());
    buf.close();
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_WidePath_Success)
{
    WinFileStreamBuf buf;
    EXPECT_TRUE(buf.open(test_path_.wstring(), std::ios_base::out));
    EXPECT_TRUE(buf.is_open());
    buf.close();
}

TEST_F(WinFileStreamBufTest, Open_InvalidDirectory_Fails)
{
    WinFileStreamBuf buf;
    EXPECT_FALSE(buf.open("Z:\\nonexistent_dir_xyz\\file.txt", std::ios_base::out));
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_AppendMode_CreatesFile)
{
    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
        const char msg[] = "first";
        buf.sputn(msg, 5);
        buf.close();
    }

    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out | std::ios_base::app));
        const char msg[] = "second";
        buf.sputn(msg, 6);
        buf.close();
    }

    const auto content = read_file(test_path_);
    EXPECT_EQ(content, "firstsecond");
}

TEST_F(WinFileStreamBufTest, Open_AppendMode_NewFile)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out | std::ios_base::app));
    const char msg[] = "hello";
    buf.sputn(msg, 5);
    buf.close();

    EXPECT_EQ(read_file(test_path_), "hello");
}

TEST_F(WinFileStreamBufTest, Reopen_ClosesExistingHandle)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));

    auto second_path = test_path_;
    second_path.replace_extension(".second.txt");
    ASSERT_TRUE(buf.open(second_path.string(), std::ios_base::out));

    EXPECT_TRUE(buf.is_open());
    buf.close();
}

TEST_F(WinFileStreamBufTest, Close_WhenAlreadyClosed_NoOp)
{
    WinFileStreamBuf buf;
    buf.close();
    buf.close();
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Sync_WhenClosed_ReturnsNegative)
{
    WinFileStreamBuf buf;
    EXPECT_EQ(buf.pubsync(), -1);
}

TEST_F(WinFileStreamBufTest, Sync_WhenOpen_ReturnsZero)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
    EXPECT_EQ(buf.pubsync(), 0);
    buf.close();
}

TEST_F(WinFileStreamBufTest, Overflow_AfterClose_ReturnsEOF)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
    buf.close();

    // After close(), setp(nullptr, nullptr) is called, so the next sputc
    // immediately invokes overflow(), which returns EOF for a closed stream.
    EXPECT_EQ(buf.sputc('A'), std::char_traits<char>::eof());
}

TEST_F(WinFileStreamBufTest, Overflow_WhenOpen_WritesChar)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));

    // Write BUFFER_SIZE - 1 bytes via sputn (fills buffer without flushing)
    std::string filler(WinFileStreamBuf::BUFFER_SIZE - 1, 'X');
    buf.sputn(filler.c_str(), static_cast<std::streamsize>(filler.size()));

    // sputc fills the last slot (no overflow yet, just pptr == epptr)
    buf.sputc('Z');

    // Now pptr == epptr; next sputc triggers overflow() -> flush -> insert
    auto result = buf.sputc('Y');
    EXPECT_NE(result, std::char_traits<char>::eof());

    buf.close();

    auto content = read_file(test_path_);
    EXPECT_EQ(content.size(), WinFileStreamBuf::BUFFER_SIZE + 1);
    EXPECT_EQ(content.back(), 'Y');
}

TEST_F(WinFileStreamBufTest, Xsputn_WhenClosed_ReturnsZero)
{
    WinFileStreamBuf buf;
    const char data[] = "test";
    EXPECT_EQ(buf.sputn(data, 4), 0);
}

TEST_F(WinFileStreamBufTest, Xsputn_LargeWrite_MultipleFlushes)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));

    // Write more than 2x buffer size to force multiple flushes
    const size_t size = WinFileStreamBuf::BUFFER_SIZE * 3;
    std::string data(size, 'A');
    const auto written = buf.sputn(data.c_str(), static_cast<std::streamsize>(size));
    EXPECT_EQ(static_cast<size_t>(written), size);

    buf.close();
    EXPECT_EQ(read_file(test_path_).size(), size);
}

TEST_F(WinFileStreamBufTest, Xsputn_ZeroCount_ReturnsZero)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
    EXPECT_EQ(buf.sputn("test", 0), 0);
    buf.close();
}

TEST_F(WinFileStreamBufTest, DestructorFlushes_RAII)
{
    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(test_path_.string(), std::ios_base::out));
        const char msg[] = "raii_data";
        buf.sputn(msg, 9);
        // Destructor should flush and close
    }
    EXPECT_EQ(read_file(test_path_), "raii_data");
}

// --- WinFileStream (ostream wrapper) tests ---

class WinFileStreamTest : public WinFileStreamBufTest
{
};

TEST_F(WinFileStreamTest, DefaultConstruct_NotOpen)
{
    WinFileStream stream;
    EXPECT_FALSE(stream.is_open());
}

TEST_F(WinFileStreamTest, ConstructWithPath_OpensFile)
{
    WinFileStream stream(test_path_.string());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, ConstructWithPath_InvalidPath_SetsFailbit)
{
    WinFileStream stream("Z:\\nonexistent_dir_xyz\\file.txt");
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, Open_NarrowPath_Success)
{
    WinFileStream stream;
    stream.open(test_path_.string());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, Open_WidePath_Success)
{
    WinFileStream stream;
    stream.open(test_path_.wstring());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, Open_InvalidNarrowPath_SetsFailbit)
{
    WinFileStream stream;
    stream.open("Z:\\nonexistent_dir_xyz\\file.txt");
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, Open_InvalidWidePath_SetsFailbit)
{
    WinFileStream stream;
    stream.open(std::wstring(L"Z:\\nonexistent_dir_xyz\\file.txt"));
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, StreamWrite_VerifyContent)
{
    {
        WinFileStream stream(test_path_.string());
        ASSERT_TRUE(stream.is_open());
        stream << "Hello, " << 42 << "!";
        stream.flush();
    }
    EXPECT_EQ(read_file(test_path_), "Hello, 42!");
}

TEST_F(WinFileStreamTest, Close_ExplicitClose)
{
    WinFileStream stream(test_path_.string());
    ASSERT_TRUE(stream.is_open());
    stream.close();
    EXPECT_FALSE(stream.is_open());
}

TEST_F(WinFileStreamTest, DestructorFlushes_RAII)
{
    {
        WinFileStream stream(test_path_.string());
        ASSERT_TRUE(stream.is_open());
        stream << "destructor_test";
    }
    EXPECT_EQ(read_file(test_path_), "destructor_test");
}

TEST_F(WinFileStreamTest, ConcurrentRead_WhileWriting)
{
    WinFileStream stream(test_path_.string());
    ASSERT_TRUE(stream.is_open());
    stream << "shared_access";
    stream.flush();

    // FILE_SHARE_READ should allow concurrent reads
    HANDLE h = CreateFileW(
        test_path_.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }
}

TEST_F(WinFileStreamTest, AppendMode_AppendsToExisting)
{
    {
        WinFileStream stream(test_path_.string());
        stream << "part1";
    }
    {
        WinFileStream stream;
        stream.open(test_path_.string(), std::ios_base::out | std::ios_base::app);
        ASSERT_TRUE(stream.is_open());
        stream << "part2";
    }
    EXPECT_EQ(read_file(test_path_), "part1part2");
}

TEST_F(WinFileStreamTest, FlushBuffer_EmptyBuffer_Succeeds)
{
    WinFileStream stream(test_path_.string());
    ASSERT_TRUE(stream.is_open());
    // Flush without writing anything
    stream.flush();
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamBufTest, Open_AcpFallback_InvalidUtf8)
{
    WinFileStreamBuf buf;
    // Build a path string with invalid UTF-8 bytes directly, bypassing
    // std::filesystem::path which throws on invalid sequences.
    std::string dir = test_dir_.string();
    std::string invalid_utf8 = dir + "\\test_\x80\x81.txt";

    // MultiByteToWideChar with CP_UTF8 + MB_ERR_INVALID_CHARS should fail,
    // triggering the CP_ACP fallback path.
    bool result = buf.open(invalid_utf8, std::ios_base::out);
    if (result)
    {
        buf.close();
        // Clean up - use Win32 API since std::filesystem can't handle the name
        std::wstring wide_invalid;
        wide_invalid.resize(MAX_PATH);
        int len = MultiByteToWideChar(CP_ACP, 0, invalid_utf8.c_str(), -1, wide_invalid.data(), MAX_PATH);
        if (len > 0)
        {
            DeleteFileW(wide_invalid.c_str());
        }
    }
}

TEST_F(WinFileStreamTest, ConstructWithPath_WritesData)
{
    // Exercises constructor WinFileStream(const std::string&, openmode)
    WinFileStream stream(test_path_.string(), std::ios_base::out);
    ASSERT_TRUE(stream.is_open());
    stream << "ctor_test";
    stream.close();
    EXPECT_EQ(read_file(test_path_), "ctor_test");
}

TEST_F(WinFileStreamTest, DefaultConstruct_ThenOpen_ThenWrite)
{
    // Exercises default constructor + separate open
    WinFileStream stream;
    EXPECT_FALSE(stream.is_open());
    stream.open(test_path_.string());
    ASSERT_TRUE(stream.is_open());
    stream << "default_ctor";
    stream.close();
    EXPECT_EQ(read_file(test_path_), "default_ctor");
}

TEST_F(WinFileStreamTest, Destructor_ClosesFile)
{
    // Verify the destructor properly closes by checking no handle leak
    {
        WinFileStream stream(test_path_.string());
        stream << "dtor_test";
    }
    // After destruction, we should be able to open and truncate the file
    WinFileStream stream2(test_path_.string());
    EXPECT_TRUE(stream2.is_open());
    stream2 << "overwritten";
    stream2.close();
    EXPECT_EQ(read_file(test_path_), "overwritten");
}
