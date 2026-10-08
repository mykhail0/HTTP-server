#include "server.hpp"

#include <sys/socket.h>

#include <fstream>

constexpr std::string_view server::code_string_view(
    server::status_code status) {
  switch (status) {
    case status_code::OK:
      return "OK";
    case status_code::FOUND:
      return "Found";
    case status_code::BAD_REQUEST:
      return "Bad Request";
    case status_code::NOT_FOUND:
      return "Not Found";
    case status_code::INTERNAL_SERVER_ERROR:
      return "Internal Server Error";
    case status_code::NOT_IMPLEMENTED:
      return "Not Implemented";
    default:
      throw std::invalid_argument("Unknown status code");
  }
}

bool server::full_send(socket_wrapper const& client, std::string_view s) {
  size_t sent = 0;
  ssize_t length;
  do {
    if (-1 == (length = send(client.get(), s.data() + sent, s.size() - sent,
                             MSG_NOSIGNAL))) {
      if (errno == EINTR) {
        // If interrupted by a signal, try again.
        continue;
      }
      perror("send");
      return false;
    }
    sent += length;
  } while (sent < s.size());
  return true;
}

bool server::send_status(socket_wrapper const& client, status_code status,
                         size_t len, const std::string& additional_headers) {
  // Could also compute expected length for s.reserve to preallocate.
  std::string s("HTTP/1.1 ");
  s.append(std::to_string(static_cast<int>(status)))
      .append(" ")
      .append(code_string_view(status))
      .append("\r\ncontent-length: ")
      .append(std::to_string(len))
      .append("\r\n")
      .append(additional_headers)
      .append("\r\n");
  return full_send(client, s);
}

bool server::send_file(socket_wrapper const& client, std::ifstream& ifs,
                       size_t sz) {
  std::array<char, 4000> buffer;
  size_t was_read = 0;
  do {
    size_t was_read_locally = 0;
    try {
      ifs.read(buffer.data(), buffer.size());
    } catch (std::exception& e) {
      perror(e.what());
      return false;
    }
    size_t delta = ifs.gcount();

    if (not full_send(client, std::string_view(buffer.data() + was_read_locally,
                                               delta))) {
      return false;
    }
    was_read_locally += delta;
    was_read += delta;

  } while (was_read < sz);
  return not ifs.bad();
}

bool server::find_and_send(socket_wrapper const& client,
                           std::string const& method_str,
                           std::filesystem::path const& resource,
                           std::string const& additional_headers) {
  std::filesystem::path resource_path = params.get_path() / resource;
  size_t len = std::filesystem::file_size(resource_path);
  std::ifstream res_ifs(resource_path);
  if (res_ifs.is_open()) {
    if (not send_status(client, status_code::OK, len, additional_headers)) {
      return false;
    }
    if (method_str == "HEAD") return true;
    return send_file(client, res_ifs, len);
  }
  return false;
}

bool server::process_request(socket_wrapper const& client,
                             const std::string& method_str,
                             const std::string& resource,
                             bool close_connection) {
  std::string additional_header =
      close_connection ? "connection: close\r\n" : "";
  std::filesystem::path resource_path{resource};
  if (auto valid_path = parser_.validate_path(resource_path)) {
    bool can_try_locally = *(valid_path->lexically_normal().begin()) != "..";
    if (can_try_locally) {
      try {
        return find_and_send(client, method_str, valid_path.value(),
                             additional_header);
      } catch (std::filesystem::filesystem_error& e) {
      }
    }
    // Correlated servers.
    auto it = params.get_correlated_servers().find(resource);
    if (it != params.get_correlated_servers().end()) {
      auto& [server, port] = it->second;
      std::string additional_headers("location: ");
      additional_headers.append("http://")
          .append(server)
          .append(":")
          .append(port)
          .append(resource)
          .append("\r\n")
          .append(additional_header);
      return send_status(client, status_code::FOUND, 0, additional_headers);
    }
    return send_status(client, status_code::NOT_FOUND, 0, additional_header);
  }
  send_status(client, status_code::BAD_REQUEST, 0, "connection: close\r\n");
  return false;
}

// Once connected to client, exchange http messages with it.
void server::talk_to_client(socket_wrapper&& client) {
  std::string str;
  size_t i = 0;
  bool close_connection = false;
  while (not close_connection) {
    std::string method_str, resource_str;
    if (not parser_.parse_request_line(client, str, i, method_str,
                                       resource_str)) {
      send_status(client, status_code::BAD_REQUEST, 0, "connection: close\r\n");
      break;
    }
    bool request_implemented = true;
    if (method_str != "GET" and method_str != "HEAD") {
      if (not send_status(client, status_code::NOT_IMPLEMENTED, 0, "")) break;
      request_implemented = false;
    }
    if (not parser_.parse_headers(client, str, i, close_connection)) {
      send_status(client, status_code::BAD_REQUEST, 0, "connection: close\r\n");
      break;
    }

    // If request is of type GET or HEAD, we can parse it meaningfully.
    if (request_implemented) {
      if (not process_request(client, method_str, resource_str,
                              close_connection))
        break;
    }
  }
}

// Connect to different client and then talk to them.
int server::run_server() {
  // FIXME with filesystem::path
  // if (path.back() != '/') path += "/";
  while (true) {
    if (auto client_socket = listener_socket.accept_incoming()) {
      // Whene there is a timeout, program processes it as an error in recv() or
      // send().
      if (client_socket->set_timeout(
              socket_wrapper::timeout_category::receive)) {
        if (client_socket->set_timeout(
                socket_wrapper::timeout_category::send)) {
          talk_to_client(std::move(client_socket.value()));
        }
      }
    }
  }
}
