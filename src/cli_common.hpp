// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <string>

#include "logging.hpp"

namespace aegis {

int usage(const char* prog);

/**
 * Print the agent version string to stdout, followed by newline.
 * Returns 0. Intended as the return value of a dispatcher branch for
 * `aegisbpf --version`, `aegisbpf -V`, or `aegisbpf version`.
 */
int print_version();

LogLevel parse_log_level(const std::string& value);
void configure_logging_from_args(int argc, char** argv);

} // namespace aegis
