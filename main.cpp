    #include <pcap.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <algorithm>
    #include <cstdio>
    #include <cstring>
    #include <string>
    #include <vector>

    #include "ethhdr.h"
    #include "ip.h"
    #include "tcp.h"

    int main(int argc, char* argv[]) {
        if (argc != 3) {
            printf("syntax : tcp-block <interface> <pattern>\n");
            printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
            return -1;
        }

        char* dev = argv[1];
        std::string pattern = argv[2];
        if (pattern.empty()) return -1;

        const char msg[] =
            "HTTP/1.0 302 Redirect\r\n"
            "Location: http://warning.or.kr\r\n"
            "\r\n";
        const int msgSize = sizeof(msg) - 1;

        auto sum = [](const uint8_t* p, int len) {
            uint32_t s = 0;

            while (len > 1) {
                s += (uint16_t(p[0]) << 8) | p[1];
                p += 2;
                len -= 2;
            }

            if (len)
                s += uint16_t(p[0]) << 8;

            while (s >> 16)
                s = (s & 0xFFFF) + (s >> 16);

            return htons(uint16_t(~s));
        };

        auto tcpSum = [&](IpHdr* ip, TcpHdr* tcp, int dataSize) {
            int len = sizeof(TcpHdr) + dataSize;
            std::vector<uint8_t> b(12 + len, 0);

            memcpy(&b[0], &ip->sip_, 4);
            memcpy(&b[4], &ip->dip_, 4);
            b[9] = IpHdr::TCP;

            uint16_t n = htons(len);
            memcpy(&b[10], &n, 2);
            memcpy(&b[12], tcp, len);

            return sum(b.data(), b.size());
        };

        int sd = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr{};

        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

        if (sd < 0 || ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
            perror("interface mac");
            return -1;
        }

        close(sd);

        Mac myMac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

        if (handle == nullptr) {
            fprintf(stderr, "%s\n", errbuf);
            return -1;
        }

        int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        int on = 1;

        if (raw < 0 || setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("raw socket");
            return -1;
        }

        printf("tcp-block %s \"%s\"\n", dev, pattern.c_str());

        while (true) {
            struct pcap_pkthdr* hdr;
            const u_char* packet;

            int res = pcap_next_ex(handle, &hdr, &packet);

            if (res == 0) continue;
            if (res <= 0) break;

            if (hdr->caplen < sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr))
                continue;

            EthHdr* eth = reinterpret_cast<EthHdr*>(const_cast<u_char*>(packet));
            IpHdr* ip = reinterpret_cast<IpHdr*>(
                const_cast<u_char*>(packet) + sizeof(EthHdr)
            );

            if (eth->type() != EthHdr::Ip4 ||
                ip->version() != 4 ||
                ip->p() != IpHdr::TCP ||
                ip->hlen() < IpHdr::MinSize ||
                (ip->off() & 0x3FFF) != 0)
                continue;

            if (hdr->caplen < sizeof(EthHdr) + ip->hlen() + TcpHdr::MinSize ||
                ip->tlen() < ip->hlen() + TcpHdr::MinSize)
                continue;

            TcpHdr* tcp = reinterpret_cast<TcpHdr*>(
                reinterpret_cast<uint8_t*>(ip) + ip->hlen()
            );

            if (tcp->len() < TcpHdr::MinSize ||
                ip->tlen() < ip->hlen() + tcp->len())
                continue;

            int dataSize = ip->tlen() - ip->hlen() - tcp->len();

            if (dataSize <= 0 ||
                hdr->caplen < sizeof(EthHdr) + ip->tlen())
                continue;

            uint8_t* data =
                reinterpret_cast<uint8_t*>(tcp) + tcp->len();

            if (std::search(
                    data,
                    data + dataSize,
                    pattern.begin(),
                    pattern.end()
                ) == data + dataSize)
                continue;

            // Forward: client -> server, RST + ACK
            uint8_t forward[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)]{};

            EthHdr* fe = reinterpret_cast<EthHdr*>(forward);
            IpHdr* fi = reinterpret_cast<IpHdr*>(forward + sizeof(EthHdr));
            TcpHdr* ft = reinterpret_cast<TcpHdr*>(
                forward + sizeof(EthHdr) + sizeof(IpHdr)
            );

            fe->dmac_ = eth->dmac_;
            fe->smac_ = myMac;
            fe->type_ = htons(EthHdr::Ip4);

            fi->v_hl_ = 0x45;
            fi->tos_ = ip->tos_;
            fi->tlen_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
            fi->id_ = ip->id_;
            fi->off_ = 0;
            fi->ttl_ = ip->ttl_;
            fi->p_ = IpHdr::TCP;
            fi->sip_ = ip->sip_;
            fi->dip_ = ip->dip_;

            ft->sport_ = tcp->sport_;
            ft->dport_ = tcp->dport_;
            ft->seq_ = htonl(tcp->seq() + dataSize);
            ft->ack_ = tcp->ack_;
            ft->off_rsvd_ = 5 << 4;
            ft->flags_ = TcpHdr::RST | TcpHdr::ACK;

            ft->sum_ = tcpSum(fi, ft, 0);
            fi->sum_ = sum(reinterpret_cast<uint8_t*>(fi), sizeof(IpHdr));

            pcap_sendpacket(handle, forward, sizeof(forward));

            // Backward: server -> client, FIN + ACK + HTTP Redirect
            uint8_t backward[sizeof(IpHdr) + sizeof(TcpHdr) + msgSize]{};

            IpHdr* bi = reinterpret_cast<IpHdr*>(backward);
            TcpHdr* bt = reinterpret_cast<TcpHdr*>(
                backward + sizeof(IpHdr)
            );

            bi->v_hl_ = 0x45;
            bi->tos_ = ip->tos_;
            bi->tlen_ = htons(sizeof(backward));
            bi->id_ = ip->id_;
            bi->off_ = 0;
            bi->ttl_ = 128;
            bi->p_ = IpHdr::TCP;
            bi->sip_ = ip->dip_;
            bi->dip_ = ip->sip_;

            bt->sport_ = tcp->dport_;
            bt->dport_ = tcp->sport_;
            bt->seq_ = tcp->ack_;
            bt->ack_ = htonl(tcp->seq() + dataSize);
            bt->off_rsvd_ = 5 << 4;
            bt->flags_ = TcpHdr::FIN | TcpHdr::ACK;

            memcpy(
                backward + sizeof(IpHdr) + sizeof(TcpHdr),
                msg,
                msgSize
            );

            bt->sum_ = tcpSum(bi, bt, msgSize);
            bi->sum_ = sum(reinterpret_cast<uint8_t*>(bi), sizeof(IpHdr));

            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = bi->dip_;

            sendto(
                raw,
                backward,
                sizeof(backward),
                0,
                reinterpret_cast<sockaddr*>(&addr),
                sizeof(addr)
            );

            printf("blocked\n");
        }

        close(raw);
        pcap_close(handle);
        return 0;
    }