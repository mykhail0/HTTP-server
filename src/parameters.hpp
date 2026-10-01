#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <string>
#include <unordered_map>

// Helper type for server:port pairs in resource file.
using address_t = std::pair<std::string, std::string>;

// TODO add const getters and change visibility to private
// Variables needed for proper server's operation.
struct server_parameters_t {
  // Server's port number.
  std::string port_num;
  // Path to files the server should serve.
  std::string path;
  // Correlated server's addresses for given resources.
  std::unordered_map<std::string, address_t> correlated_servers;

  server_parameters_t(int argc, char* argv[]);
};

#endif  // PARAMETERS_H
