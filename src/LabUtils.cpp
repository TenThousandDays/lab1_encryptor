#include "LabUtils.h"

#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

std::filesystem::path resolveExecutablePath(const char* argv0)
{
#if defined(_WIN32)
    std::wstring buffer(MAX_PATH, L'\0');

    const DWORD size = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));

    if (size > 0 && size < buffer.size()) {
        buffer.resize(size);

        std::error_code errorCode;
        const std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(
            std::filesystem::path(buffer),
            errorCode);

        if (!errorCode) {
            return canonicalPath;
        }

        return std::filesystem::path(buffer);
    }
#endif

#if defined(__linux__)
    std::vector<char> buffer(4096, '\0');

    const ssize_t size = readlink(
        "/proc/self/exe",
        buffer.data(),
        buffer.size() - 1);

    if (size > 0) {
        buffer[static_cast<std::size_t>(size)] = '\0';

        std::error_code errorCode;
        const std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(
            std::filesystem::path(buffer.data()),
            errorCode);

        if (!errorCode) {
            return canonicalPath;
        }

        return std::filesystem::path(buffer.data());
    }
#endif

    if (argv0 == nullptr) {
        return {};
    }

    std::error_code errorCode;
    const std::filesystem::path absolutePath = std::filesystem::absolute(argv0, errorCode);

    if (errorCode) {
        return std::filesystem::path(argv0);
    }

    const std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(
        absolutePath,
        errorCode);

    if (!errorCode) {
        return canonicalPath;
    }

    return absolutePath.lexically_normal();
}
