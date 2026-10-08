#include <iostream>

#include "exceptions.hpp"
#include "parameters.hpp"
#include "server.hpp"
#include "socket.hpp"

int main(int argc, char* argv[]) {
  try {
    server_parameters params(argc, argv);
    socket_wrapper sock(params.get_port_num().c_str());
    server s(std::move(sock), std::move(params));
    s.run_server();
  } catch (const server_parameter_error& e) {
    std::cerr << "Server parameter error: " << e.what() << '\n';
    return EXIT_FAILURE;
  } catch (const socket_error& e) {
    std::cerr << "Socket acquisition error: " << e.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
