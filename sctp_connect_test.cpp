#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/sctp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace {
struct Options {
    std::string remote_ip;
    uint16_t remote_port{};
    std::string local_ip;
    std::string payload;
};

bool parse_args(int argc, char *argv[], Options &opts) {
    if (argc < 3 || argc > 5)
        return false;

    opts.remote_ip = argv[1];
    int port = std::stoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "[SCTP] invalid port number: " << port << "\n";
        return false;
    }
    opts.remote_port = static_cast<uint16_t>(port);

    if (argc >= 4)
        opts.local_ip = argv[3];

    if (argc == 5)
        opts.payload = argv[4];

    return true;
}

void usage(const char *prog) {
    std::cerr << "Usage: " << prog << " <remote_ip> <remote_port> [local_ip] [payload]\n"
              << "  remote_ip  : indirizzo IP del peer SCTP\n"
              << "  remote_port: porta SCTP del peer\n"
              << "  local_ip   : opzionale, IP locale da forzare con bind\n"
              << "  payload    : opzionale, stringa da inviare (default: solo connect)\n";
}

bool bind_local(int fd, const std::string &local_ip) {
    if (local_ip.empty())
        return true;

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    if (inet_pton(AF_INET, local_ip.c_str(), &local.sin_addr) != 1) {
        std::cerr << "[SCTP] inet_pton(local) failed for " << local_ip << "\n";
        return false;
    }

    if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
        std::cerr << "[SCTP] bind() failed errno=" << errno << " (" << strerror(errno) << ")\n";
        return false;
    }
    return true;
}

bool connect_peer(int fd, const Options &opts) {
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(opts.remote_port);
    if (inet_pton(AF_INET, opts.remote_ip.c_str(), &peer.sin_addr) != 1) {
        std::cerr << "[SCTP] inet_pton(remote) failed for " << opts.remote_ip << "\n";
        return false;
    }

    std::cerr << "[SCTP] connecting to " << opts.remote_ip << ':' << opts.remote_port;
    if (!opts.local_ip.empty())
        std::cerr << " (from " << opts.local_ip << ')';
    std::cerr << "...\n";

    if (connect(fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)) < 0) {
        std::cerr << "[SCTP] connect() failed errno=" << errno << " (" << strerror(errno) << ")\n";
        return false;
    }

    std::cerr << "[SCTP] connection established\n";
    return true;
}

void send_payload(int fd, const std::string &payload) {
    if (payload.empty())
        return;

    int ret = sctp_sendmsg(fd, payload.data(), payload.size(), nullptr, 0, 0, 0, 0, 0, 0);
    if (ret < 0)
        std::cerr << "[SCTP] sctp_sendmsg failed errno=" << errno << " (" << strerror(errno) << ")\n";
    else
        std::cerr << "[SCTP] Sent " << ret << " bytes of payload\n";
}
} // namespace

int main(int argc, char *argv[]) {
    Options opts;
    if (!parse_args(argc, argv, opts)) {
        usage(argv[0]);
        return 1;
    }

    int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (fd < 0) {
        std::cerr << "[SCTP] socket() failed errno=" << errno << " (" << strerror(errno) << ")\n";
        return 1;
    }

    sctp_initmsg init{};
    init.sinit_num_ostreams = 2;
    init.sinit_max_instreams = 2;
    init.sinit_max_attempts = 4;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init));

    bool ok = bind_local(fd, opts.local_ip) && connect_peer(fd, opts);
    if (ok)
        send_payload(fd, opts.payload);

    close(fd);
    return ok ? 0 : 1;
}
