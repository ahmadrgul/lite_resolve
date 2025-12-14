# LiteResolve

#### Video Demo: https://youtu.be/uYXH20a-_s8?si=ssJLwW669IVyp1Z8

#### Description:

**LiteResolve** is a lightweight, command-line DNS client implemented entirely in C. Unlike standard tools that rely on high-level operating system libraries like `getaddrinfo` to resolve hostnames, LiteResolve manually constructs DNS query packets from scratch, sends them over a raw UDP socket to a recursive resolver (Google's `8.8.8.8`), and parses the raw binary response byte-by-byte.

Developed as the Final Project for CS50, this application represents the culmination of the course's curriculum. The primary objective was to demonstrate a comprehensive grasp of C programming concepts by implementing a client that strictly adheres to RFC 1035 without relying on abstraction layers. It supports a wide variety of query types, including **A** (IPv4), **AAAA** (IPv6), **MX** (Mail Exchange), **CNAME** (Canonical Name), **NS** (Name Server), **PTR** (Reverse DNS), and **TXT** records.

By building the packet headers, questions, and resource records manually, this software demonstrates a deep understanding of network byte order (endianness), memory management in C, and the specific compression algorithms used in DNS packet transmission. It serves as a functional educational tool for understanding how domain names are actually resolved behind the scenes.

## Usage

To use LiteResolve, you first need to compile the source code using the included Makefile.

### Compilation

Open your terminal in the project directory and run:

```bash
make all
```

This will compile the source files located in `src/` and place the executable binary in the `bin/` directory.

### Running Queries

The syntax is simple: `./bin/resolve [type] <domain>`

**Standard IPv4 Lookup (Default):**

```bash
./bin/resolve google.com
```

**Specific Record Types:**
You can specify the record type as the first argument. Default is A.

```bash
# Look up Mail Servers for google.com
./bin/resolve MX google.com

# Look up IPv6 addresses
./bin/resolve AAAA facebook.com

# Reverse DNS Lookup (PTR)
./bin/resolve PTR 8.8.8.8
```

## Implementation Details

The project is structured modularly to separate concerns between networking, parsing, and data structures. Here is a breakdown of the key files:

### `src/main.c`

This file acts as the orchestrator of the program. It begins by validating command-line arguments and parsing the user's desired query type (e.g., converting "MX" to the internal enum `MX`). It initializes a UDP socket (`SOCK_DGRAM`) and sets up the destination `sockaddr_in` struct pointing to Google's DNS server (8.8.8.8 on port 53). After sending the query and receiving the response into a 512-byte buffer, it delegates the parsing to the `packet` module and prints the final answers to `stdout`.

### `src/packet.c` & `include/packet.h`

This module defines the high-level `DnsPacket` structure, which mirrors the actual layout of a DNS message: a header, a list of questions, and lists of resource records (answers, authorities, additionals).

  * **Serialization:** The `memcpy_packet` function serializes the struct into a linear byte stream ready for network transmission.
  * **Deserialization:** The `parse_packet` function reverses this process, reading raw bytes and populating the `DnsPacket` struct. This is where memory is dynamically allocated for the arrays of questions and records.

### `src/header.c` & `include/header.h`

This file manages the 12-byte DNS header. It handles the setting of flags (like recursion desired) and the tracking of counts (how many questions or answers are in the packet). It also manages endianness conversion (`htons`/`ntohs`) to ensure the 16-bit integers (like ID and flags) are correctly interpreted by the network.

### `src/question.c` & `include/question.h`

Responsible for the "Question" section of the packet. It includes logic to handle special cases like **PTR** records, where an IP address like `8.8.8.8` must be reversed and appended with `.in-addr.arpa` before being encoded.

### `src/utils.c` & `include/utils.h`

This is arguably the most complex module, handling the low-level string manipulation required by DNS:

  * **`encode_name`**: Converts a human-readable domain (e.g., `google.com`) into the DNS length-prefixed format (`6google3com0`).
  * **`parse_name`**: Reads encoded names from the buffer. Crucially, it implements **DNS Message Compression**. If it encounters a byte starting with `0xC0`, it recognizes it as a pointer, jumps to the specified offset in the packet to read the suffix of the domain name, and then jumps back. This prevents infinite loops and saves bandwidth.
  * **`parse_rdata`**: Parses the "Resource Data" field based on the record type (e.g., parsing a 4-byte integer for an IP or a domain name for a CNAME).

### `src/resource_record.c` & `include/resource_record.h`

This handles the parsing of Answer, Authority, and Additional records. It reads the standard fields (Type, Class, TTL, RD Length) and then uses the `parse_rdata` function from `utils.c` to interpret the variable-length data payload. It also manages the deep copying and freeing of these structures to prevent memory leaks.

### `src/query.c` & `src/response.c`

These modules wrap the standard socket system calls. `query.c` builds the random transaction ID and uses `sendto` to transmit the request. `response.c` uses `recvfrom` to block and wait for the server's reply.

## Design Choices

### Modular Architecture

Early versions of this project (v1.0) had much of the logic crammed into a single file. Later, I refactored the code into distinct modules (Header, Question, Resource Record). This adheres to the **Single Responsibility Principle**; for example, `header.c` only cares about the first 12 bytes of the packet, while `utils.c` handles the generic string encoding logic. This made debugging significantly easier, as I could isolate parsing errors to specific files.

### Manual Memory Management

DNS packets are variable in length—a response might contain one answer or twenty. Consequently, I could not use static arrays. I utilized `malloc` and `realloc` extensively to handle these dynamic structures. To prevent memory leaks, I implemented dedicated "destructor" functions (like `free_packet` and `free_rrs`) that walk through the structs and free every allocated string and pointer before the program exits.

### Handling DNS Compression

One of the biggest challenges was implementing the offset pointer logic (`0xC0`). Initially, my parser would crash on complex responses because it treated every name as a simple sequence of labels. I had to redesign `parse_name` to be recursive (or jump-based) to handle pointers that reference other names already read in the packet. This is critical because almost all real-world DNS responses use compression to reduce packet size.

### Raw Sockets vs. Libraries

I chose to use `SOCK_DGRAM` (UDP) and construct the binary payload manually rather than using `gethostbyname`. While the latter is easier, it hides the complexity of the protocol. By manually handling `htons` (Host to Network Short) conversions and byte-level buffer manipulation, I learned how data is actually physically represented on the wire.

## Acknowledgements

  * **CS50 Staff**: For providing the foundational knowledge on C, memory management, and data structures that made this project possible.
  * **RFC 1035**: The official specification by the IETF "Domain Names - Implementation and Specification," which served as the primary reference manual for packet formatting and byte-level protocol logic.