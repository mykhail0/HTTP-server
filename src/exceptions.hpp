#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <stdexcept>

class socket_error : public std::runtime_error {
 public:
  enum class kind { getaddrinfo_fail, no_socket_found, uninitialized_socket };

 private:
  kind error_kind_;
  static std::string format_message(kind ec, const std::string& detail) {
    std::string msg;
    switch (ec) {
      case kind::getaddrinfo_fail:
        msg = "Failed getaddrinfo() call";
        break;
      case kind::no_socket_found:
        msg = "Was not able to find a viable socket";
        break;
      case kind::uninitialized_socket:
        msg = "Trying to use -1 socket";
        break;
      default:
        msg = "Unknown socket error";
        break;
    }
    if (not detail.empty()) {
      msg.append(": ").append(detail);
    }
    return msg;
  }

 public:
  explicit socket_error(kind ec, const std::string& detail = "")
      : std::runtime_error(format_message(ec, detail)), error_kind_(ec) {}

  kind get_kind() const noexcept { return error_kind_; }
};

class server_parameter_error : public std::exception {
 public:
  enum class kind {
    invalid_argument_count,
    invalid_port_format,
    port_out_of_range,
    not_directory,
    not_readable_directory,
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
      case kind::not_directory:
        return "Target path is not a directory.";
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
