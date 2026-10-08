#include "parameters.hpp"

// For faccessat:
#include <fcntl.h>
#include <unistd.h>

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

std::filesystem::path validate_path(char* path_c_str) {
  std::filesystem::path path(path_c_str);
  if (not std::filesystem::is_directory(path)) {
    throw server_parameter_error(server_parameter_error::kind::not_directory);
  }
  if (faccessat(AT_FDCWD, path.c_str(), R_OK, AT_EACCESS) != 0) {
    throw server_parameter_error(
        server_parameter_error::kind::not_readable_directory);
  }
  return path;
}
}  // namespace

server_parameters::server_parameters(int argc, char* argv[]) {
  if (argc != 3 and argc != 4) {
    throw server_parameter_error(
        server_parameter_error::kind::invalid_argument_count);
  }
  port_num = parse_port_num(argc == 4 ? std::string_view(argv[3])
                                      : std::string_view{});
  path = validate_path(argv[1]);
  correlated_servers = parse_correlated_servers(argv[2]);
}
