#ifndef PROCESSINGRESULT_H
#define PROCESSINGRESULT_H

#include <cstddef>

struct ProcessingResult
{
    std::size_t encryptedFiles = 0;
    std::size_t decryptedFiles = 0;
    std::size_t skippedFiles = 0;
    std::size_t failedFiles = 0;
    std::size_t processedSymlinks = 0;
};

#endif // PROCESSINGRESULT_H
