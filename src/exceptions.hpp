#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>

// TODO add more string information for getaddrinfo failure
class socket_error : public std::exception {
 public:
  enum class kind { getaddrinfo_fail, listen_fail, no_socket_found };

 private:
  kind error_kind_;

 public:
  explicit socket_error(kind ec) noexcept : error_kind_(ec) {}

  kind get_kind() const noexcept { return error_kind_; }

  const char* what() const noexcept override {
    switch (error_kind_) {
      case kind::getaddrinfo_fail:
        return "Failed getaddrinfo() call.";
      case kind::listen_fail:
        return "Failed listen() call.";
      case kind::no_socket_found:
        return "Was not able to find a viable socket.";
      default:
        return "Unknown socket error.";
    }
  }
};

class server_parameter_error : public std::exception {
 public:
  enum class kind {
    invalid_argument_count,
    invalid_port_format,
    port_out_of_range,
    invalid_directory,
    resource_file_unopened,
    resource_file_read_error
  };

 private:
  kind error_kind_;

 public:
  explicit server_parameter_error(kind ec) noexcept : error_kind_(ec) {}

  kind get_kind() const noexcept { return error_kind_; }

  const char* what() const noexcept override {
    switch (error_kind_) {
      case kind::invalid_argument_count:
        return "Invalid number of arguments.";
      case kind::invalid_port_format:
        return "Invalid port number format or trailing characters.";
      case kind::port_out_of_range:
        return "Port number out of range for uint16_t.";
      case kind::invalid_directory:
        return "Target path is not a valid directory.";
      case kind::resource_file_unopened:
        return "Failed to open the correlated servers file.";
      case kind::resource_file_read_error:
        return "I/O error occurred while reading the correlated servers file.";
      default:
        return "Unknown server parameter error.";
    }
  }
};

#endif  // EXCEPTIONS_H
