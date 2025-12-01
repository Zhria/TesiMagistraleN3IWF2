#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/sctp.h>

static int bind_local_if_needed(int fd, const char *local_ip)
{
    if (!local_ip || !*local_ip)
        return 0; // nessun bind richiesto
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(0); // FIXED PORT 0
    if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1)
    {
        std::cerr << "[SCTP] invalid local ip: " << local_ip << "\n";
        return -1;
    }
    if (bind(fd, (sockaddr *)&local, sizeof(local)) < 0)
    {
        std::cerr << "[SCTP] bind(local) failed errno=" << errno << " (" << strerror(errno) << ")\n";
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    const char *server_ip;
    int server_port;
    const char *local_ip;
    if (argc < 3 || argc > 4)
    {
        server_ip = "192.168.17.125";
        server_port = 32222;
        local_ip = "192.168.17.93";
    }
    else
    {
        server_ip = argv[1];
        server_port = std::stoi(argv[2]);
        local_ip = (argc == 4 ? argv[3] : nullptr);
    }

    // 1) socket SCTP in modalità SEQPACKET (E2AP)
    int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (fd < 0)
    {
        perror("socket");
        return 1;
    }

    // 2) opzionale: set INITS (stream)
    sctp_initmsg init{};
    init.sinit_num_ostreams = 2;
    init.sinit_max_instreams = 2;
    init.sinit_max_attempts = 4;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init));

    // 3) (opzionale) bind a IP locale specifico, PORTA 0 (mai 36422!)
    if (bind_local_if_needed(fd, local_ip) < 0)
    {
        close(fd);
        return 1;
    }

    // 4) prepara peer
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &peer.sin_addr) != 1)
    {
        perror("inet_pton(server)");
        close(fd);
        return 1;
    }

    std::cerr << "[SCTP] Connecting to " << server_ip << ":" << server_port;
    if (local_ip && *local_ip)
        std::cerr << "  (from " << local_ip << ")";
    std::cerr << " ...\n";

    // 5) connect
    if (connect(fd, (sockaddr *)&peer, sizeof(peer)) < 0)
    {
        std::cerr << "[SCTP] connect() failed errno=" << errno << " (" << strerror(errno) << ")\n";
        close(fd);
        return 1;
    }

    std::cerr << "[SCTP] Connected!\n";
    close(fd);
    return 0;
}
