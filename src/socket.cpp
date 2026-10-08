#include "socket.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <optional>

#include "exceptions.hpp"

socket_wrapper::TCP_anyIP_ainfo::TCP_anyIP_ainfo() : ai() {
  ai.ai_family = AF_UNSPEC;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
}

std::optional<socket_wrapper> socket_wrapper::accept_incoming() {
  int incoming = accept(get(), nullptr, nullptr);
  if (incoming < 0) {
    perror("accept");
    return {};
  }
  return socket_wrapper(incoming);
}

socket_wrapper::socket_wrapper(int sockfd) : sockfd(sockfd) {
  if (sockfd == -1) {
    throw socket_error::kind::uninitialized_socket;
  }
}

socket_wrapper::socket_wrapper(const char* port_num) {
  int yes = 1;
  addrinfo* addr_list;
  TCP_anyIP_ainfo ai;

  int retval = getaddrinfo(nullptr, port_num, &ai.ai, &addr_list);
  if (retval != 0) {
    throw socket_error(socket_error::kind::getaddrinfo_fail,
                       gai_strerror(retval));
  }

  bool found = false;
  for (addrinfo* addr_ptr = addr_list; not found and addr_ptr != nullptr;
       addr_ptr = addr_ptr->ai_next) {
    int sockfd_ = socket(addr_ptr->ai_family, addr_ptr->ai_socktype,
                         addr_ptr->ai_protocol);
    if (sockfd_ < 0) {
      perror("socket");
      continue;
    }
    // Manage socket closing.
    socket_wrapper tmp_sck(sockfd_);
    // For socket reusability.
    if (setsockopt(tmp_sck.get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) !=
        0) {
      perror("setsockopt");
      continue;
    }
    if (bind(tmp_sck.get(), addr_ptr->ai_addr, addr_ptr->ai_addrlen) != 0) {
      perror("bind");
      continue;
    }
    found = listen(tmp_sck.get(), SOMAXCONN) != -1;
    if (found) {
      *this = std::move(tmp_sck);
    } else {
      perror("listen");
    }
  }

  freeaddrinfo(addr_list);
  if (not found) {
    throw socket_error(socket_error::kind::no_socket_found);
  }
}

socket_wrapper::socket_wrapper(socket_wrapper&& other) noexcept
    : sockfd(other.sockfd) {
  other.sockfd = -1;
}

socket_wrapper& socket_wrapper::operator=(socket_wrapper&& other) noexcept {
  if (this != &other) {
    close_socket();
    sockfd = other.sockfd;
    other.sockfd = -1;
  }
  return *this;
}

socket_wrapper::~socket_wrapper() { close_socket(); }

int socket_wrapper::get() const {
  if (sockfd == -1) {
    throw socket_error(socket_error::kind::uninitialized_socket);
  }
  return sockfd;
}

bool socket_wrapper::set_timeout(socket_wrapper::timeout_category category) {
  timeval tout;
  tout.tv_sec = 3600;
  tout.tv_usec = 0;
  int option_name;
  switch (category) {
    case socket_wrapper::timeout_category::receive:
      option_name = SO_RCVTIMEO;
      break;
    case socket_wrapper::timeout_category::send:
      option_name = SO_SNDTIMEO;
      break;
    default:
      throw std::runtime_error("unknown timeout category");
      break;
  }
  bool success =
      setsockopt(get(), SOL_SOCKET, option_name, &tout, sizeof tout) == 0;
  if (not success) {
    perror("setsockopt timeout");
  }
  return success;
}

void socket_wrapper::close_socket() {
  if (sockfd != -1) {
    if (close(sockfd) != 0) {
      perror("close(sockfd)");
    }
    sockfd = -1;
  }
}
