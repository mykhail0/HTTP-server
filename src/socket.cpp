#include "socket.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>

#include "exceptions.hpp"

socket::socket(const char* port_num) {
  int listener_fd, bind_status, yes = 1;
  listener_fd = bind_status = -1;

  addrinfo hints, *addr_list;
  std::memset(&hints, 0, sizeof hints);
  // TCP/(IPv4|IPv6)
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  int retval = getaddrinfo(nullptr, port_num, &hints, &addr_list);
  if (retval != 0) {
    // TODO add gai_strerror usage
    throw socket_error(socket_error::kind::getaddrinfo_fail);
  }

  for (addrinfo* addr_ptr = addr_list; addr_ptr != nullptr;
       addr_ptr = addr_ptr->ai_next) {
    if ((listener_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype,
                              addr_ptr->ai_protocol)) < 0) {
      perror("socket");
      continue;
    }

    // For socket reusability.
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) !=
        0) {
      perror("setsockopt");
      close_err(listener_fd);
      continue;
    }

    if ((bind_status =
             bind(listener_fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen)) < 0) {
      perror("bind");
      close_err(listener_fd);
      continue;
    }

    break;
  }

  freeaddrinfo(addr_list);

  if (listener_fd < 0 || bind_status < 0) fatal("Valid socket not found.\n");

  if (listen(listener_fd, BACKLOG) < 0) syserr("listen");

  return listener_fd;
}

// Closes the file descriptor with the error message if needed.
socket::~socket() {
  if (close(sockfd) != 0) perror("close");
}
