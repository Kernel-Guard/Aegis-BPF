// cppcheck-suppress-file missingIncludeSystem
#pragma once

#include <cstdint>
#include <string>

namespace aegis {

// Cgroup-scoped deny commands
int cmd_cgroup_deny_add_inode(const std::string& cgroup, const std::string& inode_str);
int cmd_cgroup_deny_add_ip(const std::string& cgroup, const std::string& ip);
int cmd_cgroup_deny_add_port(const std::string& cgroup, uint16_t port, const std::string& protocol_str,
                             const std::string& direction_str);
int cmd_cgroup_deny_del_inode(const std::string& cgroup, const std::string& inode_str);
int cmd_cgroup_deny_del_ip(const std::string& cgroup, const std::string& ip);
int cmd_cgroup_deny_del_port(const std::string& cgroup, uint16_t port, const std::string& protocol_str,
                             const std::string& direction_str);
int cmd_cgroup_deny_list();
int cmd_cgroup_deny_clear();

} // namespace aegis
