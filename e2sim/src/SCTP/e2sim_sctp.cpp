/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h> //for close()
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h> //for inet_ntop()
#include <assert.h>

#include "e2sim_sctp.hpp"
#include "e2sim_defs.h"
#include "n3iwf_utils.hpp"

#include <sys/types.h>
#include <netinet/sctp.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cerrno>

#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <poll.h>
#include <fcntl.h>

// Stampa gli eventi SCTP dal socket fd (non blocca se non ci sono eventi)
void sctp_print_events(int fd)
{
    char buf[1024];
    struct iovec iov;
    struct msghdr msg;
    ssize_t n;

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // Legge con MSG_DONTWAIT: non blocca
    n = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (n <= 0)
    {
        return; // nessun evento
    }

    if (msg.msg_flags & MSG_NOTIFICATION)
    {
        union sctp_notification *snp = (union sctp_notification *)buf;
        switch (snp->sn_header.sn_type)
        {
        case SCTP_ASSOC_CHANGE:
        {
            struct sctp_assoc_change *sac = &snp->sn_assoc_change;
            const char *state_str = "UNKNOWN";
            switch (sac->sac_state)
            {
            case SCTP_COMM_UP:
                state_str = "COMM_UP";
                break;
            case SCTP_COMM_LOST:
                state_str = "COMM_LOST";
                break;
            case SCTP_RESTART:
                state_str = "RESTART";
                break;
            case SCTP_SHUTDOWN_COMP:
                state_str = "SHUTDOWN_COMPLETE";
                break;
            case SCTP_CANT_STR_ASSOC:
                state_str = "CANT_START_ASSOC";
                break;
            default:
                state_str = "UNKNOWN";
                break;
            }
            logln("[SCTP_EVENT] ASSOC_CHANGE: %s (assoc=0x%x)\n",
                     state_str, sac->sac_assoc_id);
            break;
        }
        case SCTP_SHUTDOWN_EVENT:
        {
            struct sctp_shutdown_event *sse = &snp->sn_shutdown_event;
            logln("[SCTP_EVENT] SHUTDOWN (assoc=0x%x)\n", sse->sse_assoc_id);
            break;
        }
        case SCTP_SEND_FAILED_EVENT:
        {
            logln("[SCTP_EVENT] SEND_FAILED\n");
            break;
        }
        case SCTP_ADAPTATION_INDICATION:
        {
            logln("[SCTP_EVENT] ADAPTATION_INDICATION\n");
            break;
        }
        case SCTP_PARTIAL_DELIVERY_EVENT:
        {
            logln("[SCTP_EVENT] PARTIAL_DELIVERY\n");
            break;
        }
        case SCTP_REMOTE_ERROR:
        {
            logln("[SCTP_EVENT] REMOTE_ERROR\n");
            break;
        }
        default:
            logln("[SCTP_EVENT] Unknown type %u\n", snp->sn_header.sn_type);
            break;
        }
    }
}

// Ritorna fd aperto o -1 su errore
int sctp_start_client(const char *server_ip_str, int server_port, const char *local_ip /* può essere nullptr o "" */)
{
    sockaddr_in peer4{};  // solo IPv4 per semplicità
    if (inet_pton(AF_INET, server_ip_str, &peer4.sin_addr) != 1) {
        logln("[SCTP] inet_pton failed for '%s'\n", server_ip_str);
        return -1;
    }
    peer4.sin_family = AF_INET;
    peer4.sin_port   = htons(server_port);

    // socket one-to-one SCTP
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) { perror("[SCTP] socket"); return -1; }

    // *** BIND LOCALE (chiave della fix) ***
    if (local_ip && *local_ip) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port   = htons(0);             // porta effimera
        if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
            logln("[SCTP] invalid local ip: %s\n", local_ip);
            close(fd);
            return -1;
        }
        if (bind(fd, (sockaddr*)&local, sizeof(local)) < 0) {
            logln("[SCTP] bind(%s) failed: errno=%d (%s)\n", local_ip, errno, strerror(errno));
            close(fd);
            return -1;
        }
    }

    // Parametri INIT (prima della connect)
    struct sctp_initmsg init{};
    init.sinit_num_ostreams   = 2;
    init.sinit_max_instreams  = 2;
    init.sinit_max_attempts   = 8;
    init.sinit_max_init_timeo = 8000;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init));

    int t = 0; // disabilita autoclose
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_AUTOCLOSE, &t, sizeof(t));

    struct sctp_event_subscribe ev{};
    ev.sctp_data_io_event           = 1;
    ev.sctp_association_event       = 1;
    ev.sctp_address_event           = 1;
    ev.sctp_shutdown_event          = 1;
    ev.sctp_send_failure_event      = 1;
    ev.sctp_partial_delivery_event  = 1;
    ev.sctp_adaptation_layer_event  = 1;
    ev.sctp_peer_error_event        = 1;
    ev.sctp_authentication_event    = 1;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &ev, sizeof(ev));

    logln("[SCTP] Connecting %s:%d (local=%s)... ",
             server_ip_str, server_port, (local_ip && *local_ip) ? local_ip : "auto");

    // connect bloccante con poll per robustezza
    if (connect(fd, (sockaddr*)&peer4, sizeof(peer4)) == 0) {
        logln("OK (immediato)\n");
        return fd;
    }
    if (errno != EINPROGRESS && errno != EINTR) {
        logln("FAILED (errno=%d: %s)\n", errno, strerror(errno));
        close(fd);
        return -1;
    }

    struct pollfd p{.fd = fd, .events = POLLOUT, .revents = 0};
    int rc = poll(&p, 1, -1);
    if (rc <= 0) {
        logln("FAILED (poll rc=%d, errno=%d: %s)\n", rc, errno, strerror(errno));
        close(fd);
        return -1;
    }

    int soerr = 0; socklen_t sl = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0) {
        perror("[SCTP] getsockopt(SO_ERROR)");
        close(fd);
        return -1;
    }
    if (soerr) {
        logln("FAILED (SO_ERROR=%d: %s)\n", soerr, strerror(soerr));
        close(fd);
        return -1;
    }

    logln("OK\n");
    return fd;
}

int sctp_send_data(int &socket_fd, sctp_buffer_t &data)
{

    if (socket_fd < 0)
    {
        logln("[SCTP] Invalid socket\n");
        return -1;
    }

    // PPID per E2AP = 70 (decimale)
    uint32_t ppid = htonl(70);

    int sent_len = sctp_sendmsg(
        socket_fd,
        data.buffer, // puntatore ai byte
        data.len,    // lunghezza
        NULL, 0,     // dest addr = NULL perché il socket è già connesso
        ppid,        // Payload Protocol Identifier
        0,           // flags
        0,           // stream = 0
        0,           // timetolive
        0            // context
    );

    if(sent_len != data.len) {
        logln("[SCTP] sctp_sendmsg sent %d bytes, expected %d\n", sent_len, data.len);
    }

    if (sent_len == -1)
    {
        perror("[SCTP] sctp_send_data");
        return -1;
    }

    return sent_len;
}

int sctp_send_data_X2AP(int &socket_fd, sctp_buffer_t &data)
{
    int sent_len = sctp_sendmsg(socket_fd, (void *)(&(data.buffer[0])), data.len,
                                NULL, 0, (uint32_t)X2AP_PPID, 0, 0, 0, 0);

    if (sent_len == -1)
    {
        perror("[SCTP] sctp_send_data");
        exit(1);
    }
    return sent_len;
}

// esempio definizione
int sctp_receive_data(int &socket_fd, sctp_buffer_t &data)
{
    data.len = 0;
    memset(data.buffer, 0, sizeof(data.buffer));

    struct sctp_sndrcvinfo sinfo;
    int flags = 0;

    int recv_len = sctp_recvmsg(socket_fd,
                                data.buffer,
                                sizeof(data.buffer),
                                NULL, 0, &sinfo, &flags);

    if (recv_len < 0)
    {
        perror("[SCTP] recv error");
        return SCTP_RECV_ERR;
    }
    if (recv_len == 0)
    {
        logln("[SCTP] Connection closed by peer\n");
        close(socket_fd);
        return SCTP_RECV_ERR;
    }

    // Caso 1: è una notifica SCTP (non è payload E2AP)
    if (flags & MSG_NOTIFICATION)
    {
        union sctp_notification *snp = (union sctp_notification *)data.buffer;
        switch (snp->sn_header.sn_type)
        {
        case SCTP_ASSOC_CHANGE:
        {
            struct sctp_assoc_change *sac = &snp->sn_assoc_change;
            logln("[SCTP_EVENT] ASSOC_CHANGE state=%d error=%d out=%u in=%u",
                     sac->sac_state, sac->sac_error, sac->sac_outbound_streams, sac->sac_inbound_streams);
            break;
        }
        case SCTP_SHUTDOWN_EVENT:
        {
            logln("[SCTP_EVENT] SHUTDOWN\n");
            break;
        }
        case SCTP_REMOTE_ERROR:
        {
            struct sctp_remote_error *se = &snp->sn_remote_error;
            uint16_t cause = ntohs(se->sre_error);
            logln("[SCTP_EVENT] REMOTE_ERROR / ABORT, cause=%u (len=%u)", cause, ntohs(se->sre_length));
            break;
        }
        case SCTP_SEND_FAILED_EVENT:
        {
            logln("[SCTP_EVENT] SEND_FAILED\n");
            break;
        }
        case SCTP_PEER_ADDR_CHANGE: {
            struct sctp_paddr_change *pc = (struct sctp_paddr_change *)snp;
            logln("[SCTP_EVENT] PEER_ADDR_CHANGE state=%d error=%d",
            pc->spc_state, pc->spc_error);
           break;
        }
        default:
        {
            logln("[SCTP_EVENT] type=%u\n", snp->sn_header.sn_type);
            break;
        }
        }
        return SCTP_RECV_SKIP; // nessun payload da decodificare
    }

    // Caso 2: è un vero DATA chunk
    uint32_t ppid = ntohl(sinfo.sinfo_ppid);
    logln("[SCTP] Received DATA len=%d, PPID=%u, stream=%u\n",
             recv_len, ppid, sinfo.sinfo_stream);

    // salviamo il dato
    data.len = recv_len;

    // se è PPID=60 => payload E2AP valido //Ometto questo controllo
    return SCTP_RECV_E2AP;
    if (ppid >= 70 && ppid <= 79)
    {
        return SCTP_RECV_E2AP;
    }
    else
    {
        logln("[SCTP] Non-E2AP payload (PPID=%u), ignoro\n", ppid);
        return SCTP_RECV_SKIP;
    }
}
