#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <regex>

#include <cstdio>
#include <cstdint>
#include <cstring>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "err.h"

// Helper type for serwer:port pairs in resource file.
using address_t = std::pair<std::string, std::string>;

// HTTP status codes.
constexpr int OK = 200,
    FOUND = 302,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501;

// Map for info in resource file.
std::unordered_map<int, std::string> status_messages;

// Timeouts for connection with client.
constexpr int RECV_TIMEOUT = 3600, SEND_TIMEOUT = 3600;
// Max number of clients in queue.
constexpr int BACKLOG = 20;
// Used for recv().
constexpr size_t READ_BUFSIZE = 4000;
// Used for send() and read from file also.
constexpr size_t SEND_BUFSIZE = 4000;

// Count of US-ASCII.
constexpr int ASCII = 128;
// Based on `token` regex from RFC.
std::vector<bool> method(ASCII, false);
std::vector<bool> resource(ASCII, false);
// From assignment FAQ.
std::vector<bool> header_name(ASCII, false);
// I assume `header-field` is every character untill "\r\n" is met.

// Good request-target from assignment problem statement.
std::regex good_resource("[-./[:alnum:]]+");

// Headers which cannot be repeated in the request.
std::unordered_set<std::string> one_time_headers;

// Helper function for prepare_to_parse().
// `reg` is the regex of type [charset] which defines which ascii characters are ok.
// `mp` is then used for matching regexes of type [charset]*
void fill_ascii_map(const std::regex &reg, std::vector<bool> &mp) {
    for (uint8_t c = 0; c < ASCII; ++c)
        mp[c] = std::regex_match(std::string(1, (char) c), reg);
}

// Creates ascii_maps to facilitate parsing,
// fills out status message and headers to be encountered one time maps.
void prepare_for_exchange() {
    fill_ascii_map(std::regex("[-!#$%&'*+.^_`|~[:alnum:]]"), method);
    // Assume that resource can be any not white space character.
    fill_ascii_map(std::regex("[\\S]"), resource);
    fill_ascii_map(std::regex("[-_[:alnum:]]"), header_name);

    std::vector<std::string> one_timers {
        "connection", "content-type", "content-length", "server"
    };
    for (auto &s : one_timers)
        one_time_headers.insert(s);

    status_messages[OK] = "OK";
    status_messages[FOUND] = "Found";
    status_messages[BAD_REQUEST] = "Bad Request";
    status_messages[NOT_FOUND] = "Not Found";
    status_messages[INTERNAL_SERVER_ERROR] = "Internal Server Error";
    status_messages[NOT_IMPLEMENTED] = "Not Implemented";
}

// Closes the file descriptor with the error message if needed.
void close_err(int fd) {
    if (close(fd) != 0)
        perror("close");
}

// Returns a socket file descriptor the newly setup server is listening to.
int setup_server(const char *port_num) {
    int listener_fd, bind_status, yes = 1;
    listener_fd = bind_status = -1;

    addrinfo hints, *addr_list;
    memset(&hints, 0, sizeof hints);
    // TCP/(IPv4|IPv6)
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    if (getaddrinfo(nullptr, port_num, &hints, &addr_list) != 0)
        syserr("getaddrinfo");

    for (addrinfo *addr_ptr = addr_list; addr_ptr != nullptr; addr_ptr = addr_ptr->ai_next) {
        if ((listener_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol)) < 0) {
            perror("socket");
            continue;
        }

        // For socket reusability.
        if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) != 0) {
            perror("setsockopt");
            close_err(listener_fd);
            continue;
        }

        if ((bind_status = bind(listener_fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen)) < 0) {
            perror("bind");
            close_err(listener_fd);
            continue;
        }

        break;
    }

    freeaddrinfo(addr_list);

    if (listener_fd < 0 || bind_status < 0)
        fatal("Valid socket not found.\n");

    if (listen(listener_fd, BACKLOG) < 0)
        syserr("listen");

    return listener_fd;
}

// Wraps recv(). Receives data into the string `str`,
// prints an error message if needed.
ssize_t receive_data(int sockfd, std::string &str) {
    char buffer[READ_BUFSIZE];
    ssize_t len = recv(sockfd, buffer, sizeof buffer, 0);
    if (len < 0)
        perror("Reading from client socket.");
    str = std::string(buffer, len);
    return len;
}

// Helper function for parse_request_line(). Refreshes the string if needed.
bool update_if_needed(int sockfd, std::string &str, size_t &i) {
    if (i >= str.size()) {
        if (receive_data(sockfd, str) <= 0)
            return false;
        i = 0;
    }
    return true;
}

// Uses ascii map (`charset`) to parse `str` from i,
// extracting characters that pass into `res`.
// Exits on the first nonpassing character.
// If no characters extracted also returns not success (false).
bool match_charset(int sockfd, std::string &str, size_t &i, const std::vector<bool> &charset, std::string &res) {
    size_t prev_i = i;
    while (0 <= str[i] && (unsigned) str[i] < ASCII && charset[str[i]]) {
        try {
            res.push_back(str[i++]);
        } catch (std::exception &e) {
            return false;
        }
        if (!update_if_needed(sockfd, str, i))
            return false;
    }
    return prev_i != i;
}

// Matches `seq` in str[i:].
bool match_seq(int sockfd, std::string &str, size_t &i, const std::string &seq) {
    for (char c: seq) {
        if (str[i++] != c || !update_if_needed(sockfd, str, i))
            return false;
    }
    return true;
}

// Parses the request-line. In case it's not correct returns `false`.
bool parse_request_line(int sockfd, std::string &str, size_t &i, std::string &method_str, std::string &resource_str) {
    if (!update_if_needed(sockfd, str, i))
        return false;
    if (!match_charset(sockfd, str, i, method, method_str))
        return false;
    if (!match_seq(sockfd, str, i, " /"))
        return false;
    resource_str = "/";
    size_t previ = i;
    // Resource name can be empty.
    if (!match_charset(sockfd, str, i, resource, resource_str) && previ != i)
        return false;
    if (!match_seq(sockfd, str, i, " HTTP/1.1\r\n"))
        return false;
    return true;
}

// Parses headers. In case they aren't correct or
// there is a content-length header with a positive value returns `false`.
bool parse_headers(int sockfd, std::string &str, size_t &i, bool &close_connection) {
    std::unordered_set<std::string> found_one_timers;
    while (true) {
        // Match the header name.
        std::string header_str, header_arg;
        size_t prev_i = i;
        if (!match_charset(sockfd, str, i, header_name, header_str)) {
            if (prev_i == i) {
                if (str[i++] != '\r' || !update_if_needed(sockfd, str, i))
                    return false;
                if (str[i++] != '\n')
                    return false;
                break;
            }
            return false;
        }

        // Check if this header name was met previously in the request.
        std::transform(header_str.begin(), header_str.end(), header_str.begin(), ::tolower);
        if (one_time_headers.find(header_str) != one_time_headers.end()) {
            if (found_one_timers.find(header_str) != one_time_headers.end())
                return false;
             else
                found_one_timers.insert(header_str);
        }

        // Match ":".
        if (str[i++] != ':' || !update_if_needed(sockfd, str, i))
            return false;
        while (str[i] == '\t' || str[i] == ' ') {
            ++i;
            if (!update_if_needed(sockfd, str, i))
                return false;
        }

        // Match until "\r\n" is met.
        bool CRmet = false;
        while (str[i] != '\n' || not CRmet) {
            CRmet = str[i] == '\r';
            header_arg.push_back(str[i++]);
            if (!update_if_needed(sockfd, str, i))
                return false;
        }
        i++;
        if (!update_if_needed(sockfd, str, i))
            return false;
        header_arg.pop_back(); // pop '\r'

        // OWS is [ \t]
        auto j = header_arg.find_last_not_of(" \t");
        if (j != std::string::npos)
            header_arg = header_arg.substr(0, j + 1);

        if (header_str == "connection")
            close_connection = header_arg == "close";

        if (header_str == "content-length") {
            if (header_arg != "0")
                return false;
        }
    }

    return true;
}

// Sends status with len content-length and additional headers. No message.
bool send_status(int sockfd, int status, size_t len, const std::string &additional_headers) {
    size_t sent = 0;
    ssize_t length;
    std::string s =
        "HTTP/1.1 " + std::to_string(status) + " " +
        status_messages[status] + "\r\n" + "content-length: " +
        std::to_string(len) + "\r\n" + additional_headers + "\r\n";
    const char *str = s.c_str();
    do {
        length = send(sockfd, str + sent, s.size() - sent, 0);
        sent += length;
    } while (length != -1 && sent < s.size());
    if (length == -1) {
        perror("send");
        return false;
    }
    return true;
}

// Validates if path doesn't go outside the scope and if contains good characters.
// Trims the path of "/" in the beginning.
bool path_is_valid(std::string &path) {
    int diff;
    size_t pos, i;
    diff = pos = i = 0;
    if (path.back() == '/')
        return false;
    for (; i < path.size() && path[i] == '/'; ++i) {}
    path = path.substr(i); 
    for (size_t i = path.find('/', pos); i != std::string::npos; i = path.find('/', pos)) {
        if (i == pos) {
            ++pos;
            continue;
        }
        diff += (path.compare(pos, i - pos, "..") == 0 ? -1 : 1);
        if (diff < 0)
            return false;
        pos = i + 1;
    }
    return std::regex_match(path, good_resource);
}

// Transfers characters from ifs to socket using buffer of SEND_BUFSIZE size.
bool send_file(std::ifstream &ifs, size_t sz, int sockfd) {
    char buffer[SEND_BUFSIZE];
    size_t was_read = 0;
    do {
        size_t was_read_locally = 0;
        try {
            ifs.read(buffer, sizeof buffer);
        } catch (std::exception &e) {
            perror(e.what());
            return false;
        }
        size_t delta = ifs.gcount();

        size_t sent = 0;
        ssize_t length;
        do {
            length = send(sockfd, buffer + was_read_locally + sent, delta - sent, 0);
            sent += length;
        } while (length != -1 && sent < delta);
        if (length == -1) {
            perror("send file");
            return false;
        }
        was_read_locally += delta;
        was_read += delta;

    } while (was_read < sz);
    return not ifs.bad();
}

// as_read_res is request-target as read from the request.
bool process_request(int sockfd, const std::string &method_str, const std::string &as_read_res, bool close_connection, const std::string &path, const std::unordered_map<std::string, address_t> &addresses) {
    std::string addit_header = close_connection ? "connection: close\r\n" : "";
    std::string resource_str {as_read_res};
    bool valid_path = path_is_valid(resource_str);
    bool opened_successfully = true;
    if (valid_path) {
        resource_str = path + resource_str;
        size_t len = 0;
        try {
            len = std::filesystem::file_size(resource_str);
        } catch (std::filesystem::filesystem_error &e) {
            opened_successfully = false;
        }
        std::ifstream res_ifs(resource_str);
        if ((opened_successfully = (opened_successfully && res_ifs.is_open()))) {
            if (!send_status(sockfd, OK, len, addit_header))
                return false;
            if (method_str == "HEAD")
                return true;
            return send_file(res_ifs, len, sockfd);
        }
    }

    if (not valid_path || not opened_successfully) {
        // Assume that if ends at "/" then same as wasn't found.
        // Correlated servers.
        auto it = addresses.find(as_read_res);
        if (it != addresses.end()) {
            auto &[server, port] = it->second;
            std::string address = "http://" + server + ":" + port + as_read_res;
            if (!send_status(sockfd, FOUND, 0, "location: " + address + "\r\n" + addit_header))
                return false;
            return true;
        }
    }

    if (!send_status(sockfd, NOT_FOUND, 0, addit_header))
        return false;
    return true;
}

// Once connected to client, this function can exchange http messages with it.
void talk_to_client(int sockfd, const std::string &path, const std::unordered_map<std::string, address_t> &addresses) {
    std::string str;
    size_t i = 0;
    bool close_connection = false;
    while (not close_connection) {
        std::string method_str, resource_str;
        if (!parse_request_line(sockfd, str, i, method_str, resource_str)) {
            send_status(sockfd, BAD_REQUEST, 0, "connection: close\r\n");
            break;
        }
        bool req = true;
        if (method_str != "GET" && method_str != "HEAD") {
            if (!send_status(sockfd, NOT_IMPLEMENTED, 0, ""))
                break;
            req = false;
        }
        if (!parse_headers(sockfd, str, i, close_connection)) {
            send_status(sockfd, BAD_REQUEST, 0, "connection: close\r\n");
            break;
        }

        // If request is of type GET or HEAD, we can parse it meaningfully.
        if (req) {
            if (!process_request(sockfd, method_str, resource_str, close_connection, path, addresses))
                break;
        }
    }
    close_err(sockfd);
}

// Connects to different clients and then talks to them.
int run_server(int listener_fd, std::string &path, const std::unordered_map<std::string, address_t> &addresses) {
    if (path.back() != '/')
        path += "/";
    while (true) {
        int msg_sockfd;
        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof client_addr;
        if ((msg_sockfd = accept(listener_fd, (sockaddr *) &client_addr, &client_addr_len)) < 0) {
            perror("accept");
            continue;
        }

        // Whene there is a timeout, program processes it as an error in recv() or send().
        timeval recv_tout, send_tout;
        recv_tout.tv_sec = RECV_TIMEOUT;
        recv_tout.tv_usec = 0;
        if (setsockopt(msg_sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_tout, sizeof recv_tout) != 0) {
            perror("setsockopt recv timeout");
            close_err(msg_sockfd);
            continue;
        }

        send_tout.tv_sec = SEND_TIMEOUT;
        send_tout.tv_usec = 0;
        if (setsockopt(msg_sockfd, SOL_SOCKET, SO_SNDTIMEO, &send_tout, sizeof send_tout) != 0) {
            perror("setsockopt send timeout");
            close_err(msg_sockfd);
            continue;
        }

        talk_to_client(msg_sockfd, path, addresses);
    }
}

// Ignore SIGPIPE.
void block_signals() {
    struct sigaction action;
    sigset_t set, block_mask;
    if (sigemptyset(&set) == -1)
        syserr("sigemptyset");
    if (sigaddset(&set, SIGPIPE) == -1)
        syserr("sigaddset");
    if (sigemptyset(&block_mask) == -1)
        syserr("sigemptyset");
    action.sa_handler = SIG_IGN;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    if (sigaction(SIGPIPE, &action, NULL) == -1)
        syserr("sigaction");
}

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 4)
        fatal("Invalid number of arguments.\n");

    // Check if port number is OK.
    std::string port_num("8080");
    if (argc == 4) {
        port_num = argv[3];
        if (port_num.empty()) {
            port_num = "8080";
        } else {
            if (port_num.front() == '0') {
                if (port_num.size() != 1)
                    fatal("Leading zeroes in port number.\n");
            } else {
                size_t pt = port_num.find_first_not_of("0123456789");
                if (port_num.size() > 5 || pt != std::string::npos || stol(port_num) > UINT16_MAX)
                    fatal("Invalid port number.\n");
            }
        }
    }

    // Check if directory is OK.
    if (faccessat(AT_FDCWD, argv[1], R_OK, AT_EACCESS) != 0)
        syserr("Cannot open directory.");
    try {
        if (not std::filesystem::is_directory(argv[1]))
            fatal("Is not a directory.");
    } catch (std::exception &e) {
        syserr(e.what());
    }

    // Check if resource file is OK.
    std::unordered_map<std::string, address_t> addresses;
    {
        std::ifstream res_ifs(argv[2]);
        if (not res_ifs.is_open())
            syserr("Resource file not opened.");

        // Specification says that correctness of the file can be assumed.
        std::string line;
        while (std::getline(res_ifs, line)) {
            std::istringstream iss(line);
            std::string resource;
            address_t addr;
            iss >> resource >> addr.first >> addr.second;
            auto it = addresses.find(resource);
            if (it == addresses.end())
                addresses[resource] = addr;
        }
        if (res_ifs.bad())
            syserr("Error while reading resource file.");
    }

    block_signals();
    int sockfd = setup_server(port_num.c_str());
    prepare_for_exchange();
    std::string path(argv[1]);
    run_server(sockfd, path, addresses);
    close_err(sockfd);
}
