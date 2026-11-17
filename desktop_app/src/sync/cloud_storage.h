#ifndef PB_CLOUD_STORAGE_H_
#define PB_CLOUD_STORAGE_H_

#include "secure_bytes.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pb::sync {

struct remote_file {
    std::vector<std::uint8_t> data; // encrypted container, as stored remotely
    std::string rev;                // opaque revision id of this version
};

// Remote copy of the (already encrypted) vault file. Saves use optimistic
// concurrency: an upload names the revision it was based on, and fails with
// sync_conflict_exception if another device saved in the meantime.
class cloud_storage {
public:
    virtual ~cloud_storage() = default;

    // nullopt when no vault exists remotely yet.
    virtual std::optional<remote_file> download() = 0;

    // `base_rev` is the rev returned by download()/upload() that `data` was
    // derived from, or "" to create the file (fails if one already exists).
    // Returns the new rev. Throws sync_conflict_exception on a lost race.
    virtual std::string upload(byte_view data, const std::string& base_rev) = 0;

    // Deletes the remote vault. Succeeds if it does not exist.
    virtual void remove() = 0;
};

} // namespace pb::sync

#endif // PB_CLOUD_STORAGE_H_
