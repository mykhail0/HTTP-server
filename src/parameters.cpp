#include "parameters.hpp"

#include <charconv>
#include <filesystem>
#include <fstream>

#include "exceptions.hpp"

namespace {
// Parse a C string denoting a port number into std::string. Throw an exception
// if this is not a valid port number.
std::string parse_port_num(std::string_view sv) {
  if (sv.empty()) return "8080";
  uint16_t num = 0;
  auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), num);

  if (ec == std::errc::invalid_argument or ptr != sv.data() + sv.size()) {
    throw server_parameter_error(
        server_parameter_error::kind::invalid_port_format);
  }
  if (ec == std::errc::result_out_of_range) {
    throw server_parameter_error(
        server_parameter_error::kind::port_out_of_range);
  }

  return std::string(sv);
}

// Parse the resource file with correlated servers.
std::unordered_map<std::string, address_t> parse_correlated_servers(
    char* c_str) {
  std::ifstream res_ifs(c_str);
  if (not res_ifs.is_open()) {
    throw server_parameter_error(
        server_parameter_error::kind::resource_file_unopened);
  }

  std::unordered_map<std::string, address_t> correlated_servers;
  // Specification says that correctness of the file can be assumed, so not
  // validating everything.
  std::string line;
  while (std::getline(res_ifs, line)) {
    std::istringstream iss(line);
    std::string resource;
    address_t addr;
    if (std::getline(iss, resource, '\t') and
        std::getline(iss, addr.first, '\t') and
        std::getline(iss, addr.second)) {
      correlated_servers.try_emplace(resource, addr);
    }
    if (iss.bad()) {
      throw std::ios_base::failure("Error while reading resource file.");
    }
  }
  if (res_ifs.bad()) {
    throw std::ios_base::failure("Error while reading resource file.");
  }
  return correlated_servers;
}
}  // namespace

server_parameters_t::server_parameters_t(int argc, char* argv[]) {
  if (argc != 3 and argc != 4) {
    throw server_parameter_error(
        server_parameter_error::kind::invalid_argument_count);
  }
  // Check if port number is OK.
  port_num = parse_port_num(argc == 4 ? std::string_view(argv[3])
                                      : std::string_view{});

  path = argv[1];
  if (not std::filesystem::is_directory(path)) {
    throw server_parameter_error(
        server_parameter_error::kind::invalid_directory);
  }
  // Let this natively throw std::filesystem::filesystem_error on permissions
  // failure.
  std::filesystem::directory_iterator dir_check(path);
  // Instead of:
  // if (faccessat(AT_FDCWD, argv[1], R_OK, AT_EACCESS) != 0) { syserr(); }

  correlated_servers = parse_correlated_servers(argv[2]);
}
