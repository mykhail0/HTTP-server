#ifndef SERVER_H
#define SERVER_H

#include "parameters.hpp"
#include "parser.hpp"
#include "socket.hpp"

class server {
 private:
  socket_wrapper listener_socket;
  server_parameters params;
  parser parser_;

  // HTTP status codes.
  enum class status_code {
    OK = 200,
    FOUND = 302,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501
  };

  static constexpr std::string_view code_string_view(status_code status);

  // Try to send the whole of `s` to the `client`.
  bool full_send(socket_wrapper const& client, std::string_view s);

  // Send status with len content-length and additional headers. No message.
  bool send_status(socket_wrapper const& client, status_code status, size_t len,
                   const std::string& additional_headers);

  // Transfer `sz` characters from `ifs` to `client`.
  bool send_file(socket_wrapper const& client, std::ifstream& ifs, size_t sz);

  // Find a given resource and send it with given additional headers.
  // Handles both HEAD and GET specified as `method_str`.
  bool find_and_send(socket_wrapper const& client,
                     std::string const& method_str,
                     std::filesystem::path const& resource,
                     std::string const& additional_headers);

  // `resource` is request-target as read from the request.
  bool process_request(socket_wrapper const& client,
                       const std::string& method_str,
                       const std::string& resource, bool close_connection);

  void talk_to_client(socket_wrapper&& client);

 public:
  server(socket_wrapper&& sock, server_parameters&& params)
      : listener_socket(std::move(sock)), params(params) {}
  int run_server();
};

#endif  // SERVER_H
