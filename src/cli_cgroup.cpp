// cppcheck-suppress-file missingIncludeSystem
#include "cli_cgroup.hpp"

#include <cstdint>
#include <string>

#include "cli_common.hpp"
#include "commands_cgroup.hpp"
#include "logging.hpp"
#include "utils.hpp"

namespace aegis {

namespace {

bool parse_port(const std::string& value, uint16_t& port)
{
    uint64_t parsed = 0;
    if (!parse_uint64(value, parsed) || parsed == 0 || parsed > 65535) {
        logger().log(SLOG_ERROR("Invalid port").field("value", value));
        return false;
    }
    port = static_cast<uint16_t>(parsed);
    return true;
}

} // namespace

int dispatch_cgroup_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];

    if (sub != "deny")
        return usage(prog);

    if (argc < 4)
        return usage(prog);
    std::string action = argv[3];
    if (action == "list")
        return cmd_cgroup_deny_list();
    if (action == "clear")
        return cmd_cgroup_deny_clear();

    // Parse arguments for add/del
    std::string cgroup;
    std::string inode_str;
    std::string ip;
    std::string protocol = "any";
    std::string direction = "both";
    uint16_t port = 0;
    bool has_inode = false;
    bool has_ip = false;
    bool has_port = false;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--cgroup") {
            if (i + 1 >= argc)
                return usage(prog);
            cgroup = argv[++i];
        } else if (arg == "--inode") {
            if (i + 1 >= argc)
                return usage(prog);
            inode_str = argv[++i];
            has_inode = true;
        } else if (arg == "--ip") {
            if (i + 1 >= argc)
                return usage(prog);
            ip = argv[++i];
            has_ip = true;
        } else if (arg == "--port") {
            if (i + 1 >= argc)
                return usage(prog);
            if (!parse_port(argv[++i], port))
                return 1;
            has_port = true;
        } else if (arg == "--protocol") {
            if (i + 1 >= argc)
                return usage(prog);
            protocol = argv[++i];
        } else if (arg == "--direction") {
            if (i + 1 >= argc)
                return usage(prog);
            direction = argv[++i];
        } else {
            return usage(prog);
        }
    }

    if (cgroup.empty()) {
        logger().log(SLOG_ERROR("--cgroup is required for cgroup deny add/del"));
        return 1;
    }

    int selector_count = (has_inode ? 1 : 0) + (has_ip ? 1 : 0) + (has_port ? 1 : 0);
    if (selector_count != 1) {
        logger().log(SLOG_ERROR("Specify exactly one of --inode, --ip, or --port"));
        return 1;
    }

    if (action == "add") {
        if (has_inode)
            return cmd_cgroup_deny_add_inode(cgroup, inode_str);
        if (has_ip)
            return cmd_cgroup_deny_add_ip(cgroup, ip);
        if (has_port)
            return cmd_cgroup_deny_add_port(cgroup, port, protocol, direction);
        return usage(prog);
    }
    if (action == "del") {
        if (has_inode)
            return cmd_cgroup_deny_del_inode(cgroup, inode_str);
        if (has_ip)
            return cmd_cgroup_deny_del_ip(cgroup, ip);
        if (has_port)
            return cmd_cgroup_deny_del_port(cgroup, port, protocol, direction);
        return usage(prog);
    }

    return usage(prog);
}

} // namespace aegis
