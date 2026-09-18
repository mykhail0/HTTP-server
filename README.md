# HTTP-server

Simplistic HTTP-server with limited functionality written in C/C++.

## Introduction

This project implements a narrow subset of HTTP/1.1 specification, with specific
behavior in case of resources requested by a client which are unavailable.
Project is written in C/C++ with the use of socket programming.

## Running

`server <path-to-directory-with-files> <file-with-correlated-servers> [<server's-port's-number>]`

Argument with directory's path is a required parameter and can use either
absolute or relative paths. In case of relative paths, the server tries to find
the given directory in the current working directory. Argument with a link to a
list of correlated servers is also a required parameter, whose function is
specified in a later [section](#correlated-servers). Argument with a port's
number is optional, equal to 8080 by default. The server listens to incoming
connections from clients on this port.

A `makefile` file is supplied with the project which produces the `server`
binary. It also includes a `clean` target.

## Specification

On launch, the server finds a given directory with files and starts waiting for
incoming TCP connections on a given port. If either opening the directory,
reading from the directory, opening the file for correlated servers or opening a
network socket does not succeed, the server exits with `EXIT_FAILURE` error
code.

After establishing a connection with a client, the server waits for a client's
request. The server terminates the connection in case of an incorrect request
from a client, after sending an error message with status 400. If the request
is correct, the server waits for more requests from the same client or until the
connection is terminated by the client.

### Communication specification

Every message between a client and the server is of the following form:

```text
HTTP-message = start-line
               *( header-field CRLF )
               CRLF
               [ message-body ]
```

More about this format can be read in the "3. Message format" chapter in the
official
[documentation](https://www.rfc-editor.org/rfc/inline-errata/rfc7230.html) of
HTTP protocol.

#### `start-line`

##### From client

The server accepts only messages where `start-line` is of the `request-line`
format:

```text
request-line = method SP request-target SP HTTP-version CRLF
```

where:

- `method` - is a token specifying the method requested for execution on the
server by the client. Accepted methods by the server are `GET` and `HEAD`.
Method's name is case sensitive,
- `SP` - a single space character,
- `request-target` - identifies a resource on which the client requests the
execution of the given method. This cannot include a space character. In this
implementation, files' names can include onnly characters from [a-zA-Z0-9.-].
Full resource then may include characters from [a-zA-Z0-9.-/],
- `HTTP-version` - the following sequence of characters: `HTTP/1.1`,
- `CRLF` - sequence of 2 characters with ASCII values of 13 and 10.

##### From server

The server replies with messages where `start-line` is of the `status-line`
format:

```text
status-line = HTTP-version SP status-code SP reason-phrase CRLF
```

where:

- `HTTP-version` - the following sequence of characters: `HTTP/1.1`,
- `SP` - a single space character,
- `status-code` - is a number representing status code of the server's reply.
status may indicate the success of the action serverside,
- `reason-phrase` - textual description of the returned status,
- `CRLF` - sequence of 2 characters with ASCII values of 13 and 10.

#### `header-field`

This section contains zero or more lines of the following format:

```text
header-field = field-name ":" OWS field-value OWS
```

where:

- `field-name` - header's name, case insensitive. All supported header names are
listed later.
- `":"` - a single character for colon.
- `OWS` - zero or more space characters.
- `field-value` - appropriate value for the header in the HTTP protocol.

#### `message-body`

```text
[ message-body ]
```

Existence of the message body should be determined by the existence of the
`Content-Length` header beforehand.

### Server resources

The server uses a given directory path as a place to look for resources
requested by clients. Any addition/removal/modification of files is respected by
the server during its function. The server expects that requests for resources
start with the "/" character, which means the search starts at the root (the
directory path parameter at the server's startup). Next occurences of "/" are
treated as directory separators on the requested resource's path.

### Error handling

The following are codes (`status-code`) returned by the server:

- `200` - the request was executed successfully.
- `302` - requested by the client's resource has been temporarily moved to a
different location. This code is used for the extension of the protocol
implemented in this project, explained in the
[correlated servers](#correlated-servers) section.
- `400` - this code is sent always and only in cases where client's requests
do not conform to the specification.
- `404` - requested resource was not found. This code is sent when the logic in
[correlated servers](#correlated-servers) extension was taken into account.
- `500` - this code reflects an error in the server's function which was not the
client's fault.
- `501` - this code is sent when a client's request is outside of the server's
implementation. In particular, this concerns all methods other than `GET` and
`HEAD`.

Note, that in this project, described above status codes are only a section of
codes defined by the HTTP standard and are not implemented entirely consistently
with HTTP error semantics (e.g. the server does not return message body for 4xx
codes, which is not correct per RFC7231).

### Headers

The following values for `field-name` are supported:

- `Connection` - by default, a connection between a client and the server is
alive as long as the client does not terminate it or the server does not decide
the client is idle. Client can send multiple messages to the server using the
connection and expect server's answers for every message. `Connection` header
with a value of `close` allows to close the TCP connection, after receiving an
answer from the server to this message.
- `Content-Type` - describes the type of content in the body of a given HTTP
message. This implementation simply uses the value of
`application/octet-stream`.
- `Content-Length` - a non-negative integer which describes the length of a
given HTTP message's body. This is a required header for any message from the
server which contains a body.
- `Server` - optional parameter which the server may include in every message
sent to a client which identifies the server's implementation or name.

Other headers not listed are ignored. When more than one line of a supported
header is found with the same `field-name` value, the server treats the request
as incorrect.

### Supported methods

The following methods are supported:

- `GET` - try to find the specified resource and return its contents. If the
resources could not be found, proceed as described in the
[correlated servers](#correlated-servers) section.
- `HEAD` - reply the same way as if this were a `GET` method, except without any
message body. In particular, the headers should still be the same.

### Correlated servers

The file with correlated servers should have the following structure:

```text
resource TAB server TAB port
```

where:

- `resource` - absolute path of a file,
- `TAB` - tab character,
- `server` - IP 4 address of a server, which contains the given resource,
- `port` - port's number of the given server, on which it listens to incoming
connections.

If the search for a requested by a client resource failed in the file directory,
the server searches for a correlated server that contains the requested
resource. If such server is not found, then `404` is sent, otherwise `302` is
sent with the `Location` header, which value is the textual address HTTP of the
server which contains the requested resource. If a given resource is repeated
in the file, the first entry has priority. New address is constructed the
following way:

```text
PROT server COLON port resource
```

where:

- `PROT` - `http://` string,
- `server` - IP address of the server taken from the file,
- `COLON` - colon character,
- `port` - port number taken from the file,
- `resource` - absolute path to the resource, starts with "/".
