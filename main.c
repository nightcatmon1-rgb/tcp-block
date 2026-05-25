#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define proto_tcp 6
#define proto_raw 255
#define hdr_incl 3

#define tcp_fin 0x01
#define tcp_rst 0x04
#define tcp_ack 0x10

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_hdr {
    uint8_t  v_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  p;
    uint16_t sum;
    uint32_t src;
    uint32_t dst;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_res;
    uint8_t  flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};
#pragma pack(pop)

char* x;

const char* y =
    "HTTP/1.0 302 Redirect\r\n"
    "Location: http://warning.or.kr\r\n"
    "\r\n";

void usage(void) {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

uint16_t calc_sum(uint16_t* p, int n) {
    uint32_t s = 0;

    while (n > 1) {
        s += *p++;
        n -= 2;
    }

    if (n == 1) {
        s += *(uint8_t*)p;
    }

    while (s >> 16) {
        s = (s & 0xFFFF) + (s >> 16);
    }

    return (uint16_t)(~s);
}

uint16_t make_tcp_sum(
    struct ip_hdr* i,
    struct tcp_hdr* t,
    uint8_t* d,
    int l
) {
    struct fake_hdr {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    };

    struct fake_hdr h;

    int tl = sizeof(struct tcp_hdr) + l;
    int sz = sizeof(struct fake_hdr) + tl;

    uint8_t* buf = (uint8_t*)malloc(sz);

    h.src = i->src;
    h.dst = i->dst;
    h.zero = 0;
    h.proto = proto_tcp;
    h.tcp_len = htons(tl);

    memcpy(buf, &h, sizeof(h));
    memcpy(buf + sizeof(h), t, sizeof(struct tcp_hdr));

    if (l > 0) {
        memcpy(buf + sizeof(h) + sizeof(struct tcp_hdr), d, l);
    }

    uint16_t r = calc_sum((uint16_t*)buf, sz);

    free(buf);

    return r;
}

int find_pat(uint8_t* p, int n) {
    if (n <= 0) return 0;

    char* z = (char*)malloc(n + 1);

    memcpy(z, p, n);
    z[n] = '\0';

    int ok = (strstr(z, x) != NULL);

    free(z);

    return ok;
}

void send_rst_pkt(
    pcap_t* h,
    struct eth_hdr* e,
    struct ip_hdr* i,
    struct tcp_hdr* t,
    int l
) {
    uint8_t buf[1500];

    memset(buf, 0, sizeof(buf));

    struct eth_hdr* ne = (struct eth_hdr*)buf;
    struct ip_hdr* ni = (struct ip_hdr*)(buf + sizeof(struct eth_hdr));
    struct tcp_hdr* nt =
        (struct tcp_hdr*)(buf + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

    memcpy(ne->dmac, e->dmac, 6);
    memcpy(ne->smac, e->smac, 6);

    ne->type = e->type;

    ni->v_ihl = 0x45;
    ni->tos = 0;
    ni->len = htons(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
    ni->id = 0;
    ni->off = 0;
    ni->ttl = 128;
    ni->p = proto_tcp;

    ni->src = i->src;
    ni->dst = i->dst;

    ni->sum = 0;
    ni->sum = calc_sum((uint16_t*)ni, sizeof(struct ip_hdr));

    nt->sport = t->sport;
    nt->dport = t->dport;

    uint32_t q = ntohl(t->seq);
    q += l;

    nt->seq = htonl(q);
    nt->ack = t->ack;

    nt->off_res = (5 << 4);
    nt->flags = tcp_rst | tcp_ack;
    nt->win = 0;
    nt->urp = 0;

    nt->sum = 0;
    nt->sum = make_tcp_sum(ni, nt, NULL, 0);

    pcap_sendpacket(
        h,
        buf,
        sizeof(struct eth_hdr) +
        sizeof(struct ip_hdr) +
        sizeof(struct tcp_hdr)
    );
}

void send_fin_pkt(
    struct ip_hdr* i,
    struct tcp_hdr* t,
    int l
) {
    int s = socket(AF_INET, SOCK_RAW, proto_raw);

    if (s < 0) {
        perror("socket");
        return;
    }

    int one = 1;

    if (setsockopt(s, IPPROTO_IP, hdr_incl, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(s);
        return;
    }

    uint8_t buf[1500];

    memset(buf, 0, sizeof(buf));

    struct ip_hdr* ni = (struct ip_hdr*)buf;
    struct tcp_hdr* nt = (struct tcp_hdr*)(buf + sizeof(struct ip_hdr));

    uint8_t* d =
        buf + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);

    int ml = strlen(y);

    memcpy(d, y, ml);

    ni->v_ihl = 0x45;
    ni->tos = 0;
    ni->len = htons(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + ml);
    ni->id = 0;
    ni->off = 0;
    ni->ttl = 128;
    ni->p = proto_tcp;

    ni->src = i->dst;
    ni->dst = i->src;

    ni->sum = 0;
    ni->sum = calc_sum((uint16_t*)ni, sizeof(struct ip_hdr));

    nt->sport = t->dport;
    nt->dport = t->sport;

    nt->seq = t->ack;

    uint32_t a = ntohl(t->seq);
    a += l;

    nt->ack = htonl(a);

    nt->off_res = (5 << 4);
    nt->flags = tcp_fin | tcp_ack;
    nt->win = htons(65535);
    nt->urp = 0;

    nt->sum = 0;
    nt->sum = make_tcp_sum(ni, nt, d, ml);

    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ni->dst;

    sendto(
        s,
        buf,
        sizeof(struct ip_hdr) +
        sizeof(struct tcp_hdr) +
        ml,
        0,
        (struct sockaddr*)&addr,
        sizeof(addr)
    );

    close(s);
}

void cb(
    uint8_t* a,
    const struct pcap_pkthdr* h,
    const uint8_t* pkt
) {
    pcap_t* ph = (pcap_t*)a;

    struct eth_hdr* e = (struct eth_hdr*)pkt;

    if (ntohs(e->type) != 0x0800) {
        return;
    }

    struct ip_hdr* i =
        (struct ip_hdr*)(pkt + sizeof(struct eth_hdr));

    if (i->p != proto_tcp) {
        return;
    }

    int il = (i->v_ihl & 0x0F) * 4;

    struct tcp_hdr* t =
        (struct tcp_hdr*)((uint8_t*)i + il);

    int tl = ((t->off_res & 0xF0) >> 4) * 4;

    uint8_t* d = (uint8_t*)t + tl;

    int dl = ntohs(i->len) - il - tl;

    if (dl <= 0) {
        return;
    }

    if (find_pat(d, dl)) {
        printf("Blocked: %s\n", x);

        send_rst_pkt(ph, e, i, t, dl);
        send_fin_pkt(i, t, dl);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];

    x = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* h =
        pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (h == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return EXIT_FAILURE;
    }

    pcap_loop(h, 0, cb, (uint8_t*)h);

    pcap_close(h);

    return 0;
}
