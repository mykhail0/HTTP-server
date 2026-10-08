#ifndef SOCKET_H
#define SOCKET_H

#include <netdb.h>

#include <optional>

// RAII wrapper for a socket file descriptor the newly setup server is listening
// to.
class socket_wrapper {
 private:
  int sockfd = -1;
  // Closes the file descriptor with the error message if needed.
  void close_socket();

  // addrinfo hint with the following flags:
  // TCP/(IPv4|IPv6)
  class TCP_anyIP_ainfo {
   public:
    TCP_anyIP_ainfo();
    addrinfo ai;
  };

 public:
  enum class timeout_category { receive, send };
  explicit socket_wrapper(int sockfd);
  explicit socket_wrapper(const char* port_num);
  socket_wrapper(const socket_wrapper& other) = delete;
  socket_wrapper& operator=(const socket_wrapper&) = delete;
  socket_wrapper(socket_wrapper&& other) noexcept;
  socket_wrapper& operator=(socket_wrapper&& other) noexcept;
  ~socket_wrapper();

  int get() const;
  // Create a socket for accepted connection by `listener`.
  std::optional<socket_wrapper> accept_incoming();
  // Return `true` iff successfully set timeout option for the given category.
  bool set_timeout(timeout_category category);
};

#endif  // SOCKET_H
