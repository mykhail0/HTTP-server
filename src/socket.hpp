#ifndef SOCKET_H
#define SOCKET_H

// TODO what about move assignment and ctor.
// RAII wrapper for a socket file descriptor the newly setup server is listening
// to.
class socket {
 private:
  int sockfd;

 public:
  explicit socket(const char* port_num);
  socket(const socket&) = delete;
  socket& operator=(const socket&) = delete;
};

#endif  // SOCKET_H
