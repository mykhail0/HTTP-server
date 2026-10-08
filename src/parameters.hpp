#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <filesystem>
#include <string>
#include <unordered_map>

// Helper type for server:port pairs in resource file.
using address_t = std::pair<std::string, std::string>;

// Variables needed for proper server's operation.
class server_parameters {
 private:
  // Server's port number.
  std::string port_num;
  // Path to files the server should serve.
  std::filesystem::path path;
  // Correlated server's addresses for given resources.
  std::unordered_map<std::string, address_t> correlated_servers;

 public:
  server_parameters(int argc, char* argv[]);

  const std::string& get_port_num() const noexcept { return port_num; }
  const std::filesystem::path& get_path() const noexcept { return path; }
  const std::unordered_map<std::string, address_t>& get_correlated_servers()
      const noexcept {
    return correlated_servers;
  }
};

#endif  // PARAMETERS_H
