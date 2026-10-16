#include "parser.hpp"

#include <sys/socket.h>

#include <cstdint>
#include <unordered_set>

// TODO do i need unordered set?
// maybe something more ergonomic than update_if_needed callbacks?

namespace {
// recv() wrapper. Receive data into the string `str`,
// print an error message if needed.
ssize_t receive_data(socket_wrapper const& sockfd, std::string& str) {
  str.resize(4000);
  ssize_t len = 0;
  do {
    len = recv(sockfd.get(), str.data(), str.size(), 0);
  } while (len == -1 and errno == EINTR);
  if (len < 0) {
    perror("Reading from client socket.");
    return len;
  }
  str.resize(len);
  return len;
}

// `reg` is the regex of type [charset] which defines which ascii characters are
// ok. `mp` is then used for matching regexes of type [charset]*
// In short, makes an array mask based on a regex for good chars.
void fill_ascii_mask(const std::regex& reg,
                     std::array<bool, parser::ASCII>& mask) {
  for (uint8_t c = 0; c < parser::ASCII; ++c)
    mask[c] = std::regex_match(std::string(1, static_cast<char>(c)), reg);
}

// Helper function for parse_request_line(). Refresh the string if needed.
bool update_if_needed(socket_wrapper const& sockfd, std::string& str,
                      size_t& i) {
  if (i >= str.size()) {
    if (receive_data(sockfd, str) <= 0) return false;
    i = 0;
  }
  return true;
}
}  // namespace

parser::parser() {
  // Create ASCII masks to facilitate parsing.
  fill_ascii_mask(std::regex("[-!#$%&'*+.^_`|~[:alnum:]]"), method);
  // Assume that resource can be any not white space character.
  fill_ascii_mask(std::regex("[\\S]"), resource);
  fill_ascii_mask(std::regex("[-_[:alnum:]]"), header_name);
}

std::optional<std::filesystem::path> parser::validate_path(
    std::string const& path_) {
  if (path_.front() != '/' or not std::regex_match(path_, good_resource)) {
    return {};
  }
  size_t pos = path_.find_first_not_of('/');
  return std::filesystem::path(
      path_.substr(pos == std::string::npos ? path_.size() : pos));
}

// Use ASCII mask (`charset`) to parse `str` from `i`,
// extracting characters that pass into `res`.
// Exit on the first nonpassing character.
// If no characters extracted also return no success (false).
bool parser::match_charset(socket_wrapper const& sockfd, std::string& str,
                           size_t& i, const std::array<bool, ASCII>& charset,
                           std::string& res) {
  size_t prev_i = i;
  while (0 <= str[i] and (unsigned) str[i] < ASCII and charset[str[i]]) {
    try {
      res.push_back(str[i++]);
    } catch (std::exception& e) {
      return false;
    }
    if (not update_if_needed(sockfd, str, i)) return false;
  }
  return prev_i != i;
}

bool parser::match_seq(socket_wrapper const& sockfd, std::string& str,
                       size_t& i, const std::string& seq) {
  for (char c : seq) {
    if (str[i++] != c or not update_if_needed(sockfd, str, i)) return false;
  }
  return true;
}

bool parser::parse_request_line(socket_wrapper const& sockfd, std::string& str,
                                size_t& i, std::string& method_str,
                                std::string& resource_str) {
  if (not update_if_needed(sockfd, str, i)) return false;
  if (not match_charset(sockfd, str, i, method, method_str)) return false;
  if (not match_seq(sockfd, str, i, " /")) return false;
  resource_str = "/";
  size_t previ = i;
  // Resource name can be empty.
  if (not match_charset(sockfd, str, i, resource, resource_str) and previ != i)
    return false;
  if (not match_seq(sockfd, str, i, " HTTP/1.1\r\n")) return false;
  return true;
}

bool parser::parse_headers(socket_wrapper const& sockfd, std::string& str,
                           size_t& i, bool& close_connection) {
  std::unordered_set<std::string> found_one_timers;
  while (true) {
    // Match the header name.
    std::string header_str, header_arg;
    size_t prev_i = i;
    if (not match_charset(sockfd, str, i, header_name, header_str)) {
      if (prev_i == i) {
        if (str[i++] != '\r' or not update_if_needed(sockfd, str, i)) {
          return false;
        }
        if (str[i++] != '\n') {
          return false;
        }
        break;
      }
      return false;
    }

    // Check if this header name was met previously in the request.
    std::transform(header_str.begin(), header_str.end(), header_str.begin(),
                   ::tolower);
    auto end_it = end(one_time_headers);
    if (std::find(begin(one_time_headers), end_it, header_str) != end_it) {
      if (found_one_timers.find(header_str) != found_one_timers.end()) {
        return false;
      } else {
        found_one_timers.insert(header_str);
      }
    }

    // Match ":".
    if (str[i++] != ':' or not update_if_needed(sockfd, str, i)) {
      return false;
    }
    while (str[i] == '\t' or str[i] == ' ') {
      ++i;
      if (not update_if_needed(sockfd, str, i)) {
        return false;
      }
    }

    // Match until "\r\n" is met.
    bool CRmet = false;
    while (str[i] != '\n' or not CRmet) {
      CRmet = str[i] == '\r';
      header_arg.push_back(str[i++]);
      if (not update_if_needed(sockfd, str, i)) {
        return false;
      }
    }
    ++i;
    if (not update_if_needed(sockfd, str, i)) {
      return false;
    }
    header_arg.pop_back();  // pop '\r'

    // OWS is [ \t]
    auto j = header_arg.find_last_not_of(" \t");
    if (j != std::string::npos) header_arg = header_arg.substr(0, j + 1);

    if (header_str == "connection") close_connection = header_arg == "close";

    if (header_str == "content-length") {
      if (header_arg != "0") {
        return false;
      }
    }
  }

  return true;
}
