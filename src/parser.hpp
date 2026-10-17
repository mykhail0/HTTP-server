#ifndef PARSER_H
#define PARSER_H

#include <array>
#include <filesystem>
#include <regex>

#include "socket.hpp"

class parser {
 public:
  // Count of US-ASCII.
  static constexpr unsigned ASCII = 128;
  static constexpr unsigned ONE_TIME_HEADERS = 4;

 private:
  class socket_stream {
   private:
    socket_wrapper const& sockfd;
    std::string data;
    size_t read_ptr{};

    // recv() wrapper. Receive data into the string `str`,
    // print an error message if needed.
    ssize_t receive_data();

   public:
    socket_stream(socket_wrapper const& sockfd) : sockfd(sockfd) {}
    std::optional<char> peek();
    std::optional<char> get();
  };

  socket_stream sock_stream;
  // Based on `token` regex from RFC.
  static const std::array<bool, ASCII>& method();
  static const std::array<bool, ASCII>& resource();
  static const std::array<bool, ASCII>& OWS();
  static const std::array<bool, ASCII>& header_name();
  // We assume `header-field` is every character untill "\r\n" is met.

  // Good request-target, specified in the README.md.
  static const std::regex& good_resource();

  // Headers which cannot be repeated in the request.
  static const std::array<std::string, ONE_TIME_HEADERS>& one_time_headers();

  // Use ASCII mask (`charset`) to parse socket_stream extracting characters
  // that pass into `res`. Exit on the first nonmatching character.
  // If no characters extracted also return no success (false).
  bool match_charset(const std::array<bool, ASCII>& charset, std::string& res);

  // Match `seq` in data[read_ptr:].
  bool match_seq(const std::string& seq);

  // Like match_charset except not saving the matched string.
  void consume_charset(const std::array<bool, ASCII>& charset);

 public:
  parser(socket_wrapper const& sockfd) : sock_stream(sockfd) {}

  // Validate if `path` doesn't go outside the scope and if it contains good
  // characters.
  std::optional<std::filesystem::path> validate_path(std::string const& path);

  // Parse the request-line. In case it's not correct return `false`.
  bool parse_request_line(std::string& method_str, std::string& resource_str);

  // Parse headers. In case they aren't correct or
  // there is a content-length header with a positive value return `false`.
  bool parse_headers(bool& close_connection);
};

#endif  // PARSER_H
