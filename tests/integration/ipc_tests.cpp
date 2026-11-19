// Local IPC channel (named pipe / Unix socket) between the native host and
// the desktop app.
#include "ipc/local_channel.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using pb::ipc::connection;
using pb::ipc::listener;

namespace {

// A fresh endpoint per test, so tests never meet each other or the real app.
class IpcChannel : public ::testing::Test {
protected:
    void SetUp() override {
        static std::atomic<int> counter{0};
#ifdef _WIN32
        endpoint = "\\\\.\\pipe\\phylaxbox.test." + std::to_string(::GetCurrentProcessId()) + "." +
                   std::to_string(counter++);
#else
        dir = std::filesystem::temp_directory_path() /
              ("pb-ipc-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
        std::filesystem::create_directories(dir);
        ::chmod(dir.c_str(), 0700);
        endpoint = (dir / "browser.sock").string();
#endif
    }

    void TearDown() override {
        if (!dir.empty()) std::filesystem::remove_all(dir);
    }

    std::string endpoint;
    std::filesystem::path dir;
};

} // namespace

TEST(IpcEndpoint, IsPerUser) {
    const std::string e = pb::ipc::default_endpoint();
#ifdef _WIN32
    EXPECT_EQ(e.rfind("\\\\.\\pipe\\phylaxbox.browser.S-1-", 0), 0u) << e;
#else
    EXPECT_NE(e.find("phylaxbox"), std::string::npos) << e;
#endif
}

TEST_F(IpcChannel, MessagesGoBothWays) {
    auto server = listener::create(endpoint);
    ASSERT_TRUE(server);
    std::thread peer([&] {
        auto c = server->accept();
        ASSERT_TRUE(c);
        auto request = c->read();
        ASSERT_TRUE(request);
        EXPECT_TRUE(c->write("echo:" + *request));
        EXPECT_TRUE(c->write(std::string(300000, 'x'))); // larger than the pipe buffer
        EXPECT_TRUE(c->write(""));
    });

    auto client = connection::connect(endpoint);
    ASSERT_TRUE(client);
    ASSERT_TRUE(client->write("{\"type\":\"hello\"}"));
    EXPECT_EQ(client->read(), "echo:{\"type\":\"hello\"}");
    EXPECT_EQ(client->read(), std::string(300000, 'x'));
    EXPECT_EQ(client->read(), "");
    peer.join();
    EXPECT_FALSE(client->read()) << "the server closed the channel";
}

TEST_F(IpcChannel, OversizedMessagesAreRefused) {
    auto server = listener::create(endpoint);
    ASSERT_TRUE(server);
    std::thread peer([&] {
        auto c = server->accept();
        ASSERT_TRUE(c);
        EXPECT_FALSE(c->read(16)) << "17 bytes exceed the limit";
    });
    auto client = connection::connect(endpoint);
    ASSERT_TRUE(client);
    client->write("12345678901234567");
    peer.join();
    EXPECT_FALSE(client->write(std::string(pb::ipc::MAX_MESSAGE + 1, 'x')));
}

TEST_F(IpcChannel, OnlyOneListenerPerEndpoint) {
    auto first = listener::create(endpoint);
    ASSERT_TRUE(first);
    EXPECT_FALSE(listener::create(endpoint)) << "a second app instance must not take over";
}

TEST_F(IpcChannel, NothingListening) { EXPECT_FALSE(connection::connect(endpoint)); }

TEST_F(IpcChannel, CloseUnblocksAcceptAndRead) {
    auto server = listener::create(endpoint);
    ASSERT_TRUE(server);
    std::atomic<bool> accept_returned{false};
    std::thread waiting([&] {
        EXPECT_FALSE(server->accept());
        accept_returned = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    server->close();
    waiting.join();
    EXPECT_TRUE(accept_returned);

    auto server2 = listener::create(endpoint + "2");
    ASSERT_TRUE(server2);
    std::optional<connection> accepted;
    std::thread acceptor([&] { accepted = server2->accept(); });
    auto client = connection::connect(endpoint + "2");
    ASSERT_TRUE(client);
    acceptor.join();
    ASSERT_TRUE(accepted);
    std::thread reader([&] { EXPECT_FALSE(accepted->read()); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    accepted->close();
    reader.join();
}

TEST_F(IpcChannel, ListenerKeepsServingAfterAClientLeaves) {
    auto server = listener::create(endpoint);
    ASSERT_TRUE(server);
    std::thread peer([&] {
        for (int i = 0; i < 2; ++i) {
            auto c = server->accept();
            ASSERT_TRUE(c);
            auto m = c->read();
            ASSERT_TRUE(m);
            c->write(*m);
        }
    });
    for (int i = 0; i < 2; ++i) {
        auto client = connection::connect(endpoint);
        ASSERT_TRUE(client) << "client " << i;
        client->write("ping" + std::to_string(i));
        EXPECT_EQ(client->read(), "ping" + std::to_string(i));
    }
    peer.join();
}
