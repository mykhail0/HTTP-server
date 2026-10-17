#include "parser.hpp"

#include <sys/socket.h>

#include <cstdint>

namespace {
// `reg` is the regex of type [charset] which defines which ascii characters are
// ok. `mp` is then used for matching regexes of type [charset]*
// In short, makes an array mask based on a regex for good chars.
void fill_ascii_mask(const std::regex& reg,
                     std::array<bool, parser::ASCII>& mask) {
  for (uint8_t c = 0; c < parser::ASCII; ++c)
    mask[c] = std::regex_match(std::string(1, static_cast<char>(c)), reg);
}
}  // namespace

const std::array<bool, parser::ASCII>& parser::method() {
  static const std::array<bool, parser::ASCII> ans = []() {
    std::array<bool, parser::ASCII> ans;
    fill_ascii_mask(std::regex("[-!#$%&'*+.^_`|~[:alnum:]]"), ans);
    return ans;
  }();
  return ans;
}

const std::array<bool, parser::ASCII>& parser::resource() {
  static const std::array<bool, parser::ASCII> ans = []() {
    std::array<bool, parser::ASCII> ans;
    // Assume that resource can be any not white space character.
    fill_ascii_mask(std::regex("[\\S]"), ans);
    return ans;
  }();
  return ans;
}

const std::array<bool, parser::ASCII>& parser::OWS() {
  static const std::array<bool, parser::ASCII> ans = []() {
    std::array<bool, parser::ASCII> ans{};
    ans[' '] = ans['\t'] = true;
    return ans;
  }();
  return ans;
}

const std::array<bool, parser::ASCII>& parser::header_name() {
  static const std::array<bool, parser::ASCII> ans = []() {
    std::array<bool, parser::ASCII> ans;
    fill_ascii_mask(std::regex("[-_[:alnum:]]"), ans);
    return ans;
  }();
  return ans;
}

const std::regex& parser::good_resource() {
  static const std::regex ans = []() {
    return std::regex{"[-./[:alnum:]]+"};
  }();
  return ans;
}

const std::array<std::string, parser::ONE_TIME_HEADERS>&
parser::one_time_headers() {
  static const std::array<std::string, ONE_TIME_HEADERS> ans = []() {
    return std::array<std::string, ONE_TIME_HEADERS>{
        "connection", "content-type", "content-length", "server"};
  }();
  return ans;
}

ssize_t parser::socket_stream::receive_data() {
  read_ptr = 0;
  data.resize(4000);
  ssize_t len = 0;
  do {
    len = recv(sockfd.get(), data.data(), data.size(), 0);
  } while (len == -1 and errno == EINTR);
  if (len < 0) {
    perror("Reading from client socket.");
    return len;
  }
  data.resize(len);
  return len;
}

std::optional<char> parser::socket_stream::peek() {
  if (read_ptr >= data.size()) {
    if (receive_data() <= 0) return {};
  }
  return data[read_ptr];
}

std::optional<char> parser::socket_stream::get() {
  std::optional<char> ans = peek();
  if (ans) {
    ++read_ptr;
  }
  return ans;
}

std::optional<std::filesystem::path> parser::validate_path(
    std::string const& path_) {
  if (path_.front() != '/' or not std::regex_match(path_, good_resource())) {
    return {};
  }
  size_t pos = path_.find_first_not_of('/');
  return std::filesystem::path(
      path_.substr(pos == std::string::npos ? path_.size() : pos));
}

bool parser::match_charset(const std::array<bool, ASCII>& charset,
                           std::string& res) {
  size_t prev_sz = res.size();
  while (auto c = sock_stream.peek()) {
    unsigned char ch = *c;
    if (ch >= ASCII or not charset[ch]) {
      break;
    }
    res.push_back(*sock_stream.get());
  }
  return prev_sz < res.size();
}

void parser::consume_charset(const std::array<bool, ASCII>& charset) {
  while (auto c = sock_stream.peek()) {
    unsigned char ch = *c;
    if (ch < ASCII and charset[ch]) {
      sock_stream.get();
    } else {
      return;
    }
  }
}

bool parser::match_seq(const std::string& seq) {
  for (char expected : seq) {
    if (auto ch = sock_stream.get()) {
      if (ch.value() != expected) {
        return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

bool parser::parse_request_line(std::string& method_str,
                                std::string& resource_str) {
  if (not match_charset(method(), method_str) or not match_seq(" /")) {
    return false;
  }
  resource_str = "/";
  // Resource name can be empty.
  match_charset(resource(), resource_str);
  return match_seq(" HTTP/1.1\r\n");
}

bool parser::parse_headers(bool& close_connection) {
  std::array<bool, ONE_TIME_HEADERS> found_one_timers{};
  while (true) {
    // Match the header name.
    std::string header_str, header_arg;
    if (not match_charset(header_name(), header_str)) {
      return header_str.empty() and match_seq("\r\n");
    }

    // Standardize the header name.
    auto header_str_beg_it = begin(header_str);
    std::transform(header_str_beg_it, end(header_str), header_str_beg_it,
                   tolower);

    // Check if this header is one of those that can only be encountered once in
    // a request (specification).
    auto beg_it = begin(one_time_headers()), end_it = end(one_time_headers());
    auto header_it = std::find(beg_it, end_it, header_str);
    if (header_it != end_it) {
      auto header_ind = std::distance(beg_it, header_it);
      // If the header encountered, the request is ill-formed.
      if (found_one_timers[header_ind]) {
        return false;
      }
      found_one_timers[header_ind] = true;
    }

    if (not match_seq(":")) {
      return false;
    }
    consume_charset(OWS());

    // Match until "\r\n" is met.
    bool CR_met = false;
    while (sock_stream.peek() and
           not(CR_met and sock_stream.peek().value() == '\n')) {
      CR_met = sock_stream.peek().value() == '\r';
      header_arg.push_back(sock_stream.get().value());
    }
    // Stream ended or "\r\n" was met.
    if (not sock_stream.peek()) {
      return false;
    }
    // Consume the '\n'.
    sock_stream.get();
    // Pop '\r'.
    header_arg.pop_back();

    // Trim the OWS from the end of header field.
    auto j = header_arg.find_last_not_of(" \t");
    if (j != std::string::npos) {
      header_arg.resize(j + 1);
    }

    if (header_str == "connection") {
      close_connection = header_arg == "close";
    } else if (header_str == "content-length" and header_arg != "0") {
      return false;
    }
  }
}
