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

 private:
  // Based on `token` regex from RFC.
  std::array<bool, ASCII> method{};
  std::array<bool, ASCII> resource{};
  std::array<bool, ASCII> header_name{};
  // We assume `header-field` is every character untill "\r\n" is met.

  // Good request-target, specified in the README.md.
  // TODO not sure if this is legal
  std::regex good_resource{"[-./[:alnum:]]+"};

  // Headers which cannot be repeated in the request.
  std::array<std::string, 4> one_time_headers{"connection", "content-type",
                                              "content-length", "server"};

 public:
  parser();
  // Validates if `path` doesn't go outside the scope and if it contains good
  // characters.
  std::optional<std::filesystem::path> validate_path(std::string const& path);
  // Filter `str` through a given ASCII mask `charset`, extracting the matching
  // characters into `res`. Return on the first nonmatching character.
  // Return `false` if no the first character is nonmatching.
  bool match_charset(socket_wrapper const& sockfd, std::string& str, size_t& i,
                     const std::array<bool, ASCII>& charset, std::string& res);
  // Match `seq` in str[i:].
  bool match_seq(socket_wrapper const& sockfd, std::string& str, size_t& i,
                 const std::string& seq);
  // Parse the request-line. In case it's not correct return `false`.
  bool parse_request_line(socket_wrapper const& sockfd, std::string& str,
                          size_t& i, std::string& method_str,
                          std::string& resource_str);
  // Parse headers. In case they aren't correct or
  // there is a content-length header with a positive value return `false`.
  bool parse_headers(socket_wrapper const& sockfd, std::string& str, size_t& i,
                     bool& close_connection);
};

#endif  // PARSER_H
