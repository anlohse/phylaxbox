#ifndef PB_ASYNC_BIND_H_
#define PB_ASYNC_BIND_H_

#include "serial_worker.h"

#include <sodium.h>
#include <webview/webview.h>

#include <atomic>
#include <functional>
#include <string>

namespace pb::app {

using bridge_call = std::function<std::string(const std::string& request)>;

// Exposes `call` to the page as window.<name>(...) -> Promise. The UI thread
// only queues the request; `worker` runs it (Argon2id takes about a second)
// and the promise is resolved from there (webview dispatches it to the UI
// thread). The request copy, which may hold a password, is wiped after use.
// Once `closing` is set, results are dropped instead of touching the window.
inline void bind_async(webview::webview& w, serial_worker& worker,
                       const std::atomic<bool>& closing, const std::string& name,
                       bridge_call call) {
    w.bind(
        name,
        [&w, &worker, &closing, call](std::string id, std::string request, void* /*arg*/) {
            worker.post([&w, &closing, call, id, request]() mutable {
                const std::string reply = call(request);
                sodium_memzero(request.data(), request.size());
                if (!closing) {
                    w.resolve(id, 0, reply);
                }
            });
        },
        nullptr);
}

} // namespace pb::app

#endif // PB_ASYNC_BIND_H_
