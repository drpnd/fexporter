/*_
 * Copyright (c) 2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "ipfix.h"
#include "flowtable.h"

/* # of entries in the flow table */
#define FEXPORTER_FLOWTABLE_SIZE 2048

/* Default timeout in seconds */
#define FEXPORTER_DEFAULT_TIMEOUT 60

#define FEXPORTER_SNAPLEN       96
#define FEXPORTER_PROMISC       1
#define FEXPORTER_TO_MS         1


struct ipfix_template_v4 {
    int cnt;
};

/*
 * Floe exporter data structure
 */
struct fexporter {
    /* Flow table */
    flowtable_t *ft;
    /* Timeout in seconds */
    uint32_t timeout;
    /* Last flushed */
    uint64_t last_flushed;
};


/* Prototype declarations */
void usage(const char *);
uint64_t diff_timeval(struct timeval, struct timeval);
void cb_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int flush(flowtable_t *);

/*
 * Print out usage
 */
void
usage(const char *prog)
{
    fprintf(stderr, "%s: interface\n", prog);
}

/*
 * Get the difference between two timestamps in microsecond
 */
uint64_t
diff_timeval(struct timeval ts1, struct timeval ts2)
{
    uint64_t r;

    r = (ts2.tv_sec - ts1.tv_sec) * 1000000 + (ts2.tv_usec - ts1.tv_usec);

    return r;
}

/*
 * Analyze ICMP to get ICMP type and code
 */
int
analyze_icmp(const uint8_t *pkt, size_t caplen, uint16_t *type, uint16_t *code)
{
    struct icmp *icmp;

    icmp = (struct icmp *)pkt;
    if ( caplen < sizeof(struct icmp) ) {
        return -1;
    }
    *type = icmp->icmp_type;
    *code = icmp->icmp_code;

    return 0;
}

/*
 * Analyze ICMPv6 to get ICMP type and code
 */
int
analyze_icmpv6(const uint8_t *pkt, size_t caplen, uint16_t *type, uint16_t *code)
{
    struct icmp6_hdr *icmp;

    icmp = (struct icmp6_hdr *)pkt;
    if ( caplen < sizeof(struct icmp6_hdr) ) {
        return -1;
    }
    *type = icmp->icmp6_type;
    *code = icmp->icmp6_code;

    return 0;
}

/*
 * Analyze TCP to get source and destination ports
 */
int
analyze_tcp(const uint8_t *pkt, size_t caplen, uint16_t *sport, uint16_t *dport)
{
    struct tcphdr *tcp;

    tcp = (struct tcphdr *)pkt;
    if ( caplen < sizeof(struct tcphdr) ) {
        return -1;
    }
    *sport = tcp->th_sport;
    *dport = tcp->th_dport;

    return 0;
}

/*
 * Analyze UDP to get source and destination ports
 */
int
analyze_udp(const uint8_t *pkt, size_t caplen, uint16_t *sport, uint16_t *dport)
{
    struct udphdr *udp;

    udp = (struct udphdr *)pkt;
    if ( caplen < sizeof(struct udphdr) ) {
        return -1;
    }
    *sport = udp->uh_sport;
    *dport = udp->uh_dport;

    return 0;
}

/*
 * Analyze IPv4 packet
 */
int
analyze_ipv4(struct fexporter *fexprt, struct timeval ts, const uint8_t *pkt,
             size_t caplen, size_t len, size_t origlen)
{
    struct ip *ip;
    size_t hl;
    int proto;
    uint16_t sport;
    uint16_t dport;
    int ret;
    flow_t flow;
    flow_stats_t *stats;

    ip = (struct ip *)pkt;

    /* Header length */
    hl = 4 * ip->ip_hl;
    if ( caplen < hl ) {
        /* Invalid header length */
        return -1;
    }
    /* Protocol */
    proto = ip->ip_p;
    sport = 0;
    dport = 0;
    switch ( proto ) {
    case 1:
        /* ICMP */
        ret = analyze_icmp(pkt + hl, caplen - hl, &sport, &dport);
        break;
    case 6:
        /* TCP */
        ret = analyze_tcp(pkt + hl, caplen - hl, &sport, &dport);
        break;
    case 17:
        /* UDP */
        ret = analyze_udp(pkt + hl, caplen - hl, &sport, &dport);
        break;
    default:
        ret = 0;
    }
    if ( ret < 0 ) {
        return -1;
    }

    memset(&flow, 0, sizeof(flow_t));
    flow.ifindex = 0;
    flow.etype = 0x0800;
    flow.classifier.ipv4.sip.dw = ip->ip_src.s_addr;
    flow.classifier.ipv4.dip.dw = ip->ip_dst.s_addr;
    flow.classifier.ipv4.proto = proto;
    flow.classifier.ipv4.sport = sport;
    flow.classifier.ipv4.dport = dport;

    /* Update statistics */
    stats = flowtable_search(fexprt->ft, &flow);
    if ( NULL == stats  ) {
        flush(fexprt->ft);
        stats = flowtable_search(fexprt->ft, &flow);
        if ( NULL == stats  ) {
            return -1;
        }
    }
    if ( !stats->start_usec ) {
        stats->start_usec = ts.tv_sec * 1000000 + ts.tv_usec;
    }
    stats->end_usec = ts.tv_sec * 1000000 + ts.tv_usec;
    stats->packets += 1;
    stats->octets += ntohs(ip->ip_len);

    return 0;
}

/*
 * Analyze IPv6 packet
 */
int
analyze_ipv6(struct fexporter *fexprt, struct timeval ts, const uint8_t *pkt,
             size_t caplen, size_t len, size_t origlen)
{
    struct ip6_hdr *ip;
    int proto;
    uint16_t sport;
    uint16_t dport;
    int ret;
    size_t hl;
    flow_t flow;
    flow_stats_t *stats;

    ip = (struct ip6_hdr *)pkt;
    hl = sizeof(struct ip6_hdr);
    if ( caplen < hl ) {
        return -1;
    }

    /* Protocol */
    proto = ip->ip6_nxt;
    sport = 0;
    dport = 0;
    switch ( proto ) {
    case 6:
        /* TCP */
        ret = analyze_tcp(pkt + hl, caplen - hl, &sport, &dport);
        break;
    case 17:
        /* UDP */
        ret = analyze_udp(pkt + hl, caplen - hl, &sport, &dport);
        break;
    case 58:
        /* ICMPv6 */
        ret = analyze_icmpv6(pkt + hl, caplen - hl, &sport, &dport);
        break;
    default:
        ret = 0;
    }
    if ( ret < 0 ) {
        return -1;
    }

    memset(&flow, 0, sizeof(flow_t));
    flow.ifindex = 0;
    flow.etype = 0x86dd;
    memcpy(flow.classifier.ipv6.sip.b, ip->ip6_src.s6_addr, 16);
    memcpy(flow.classifier.ipv6.dip.b, ip->ip6_dst.s6_addr, 16);
    flow.classifier.ipv6.proto = proto;
    flow.classifier.ipv6.sport = sport;
    flow.classifier.ipv6.dport = dport;

    /* Update statistics */
    stats = flowtable_search(fexprt->ft, &flow);
    if ( NULL == stats  ) {
        flush(fexprt->ft);
        stats = flowtable_search(fexprt->ft, &flow);
        if ( NULL == stats  ) {
            return -1;
        }
    }
    if ( !stats->start_usec ) {
        stats->start_usec = ts.tv_sec * 1000000 + ts.tv_usec;
    }
    stats->end_usec = ts.tv_sec * 1000000 + ts.tv_usec;
    stats->packets += 1;
    stats->octets += ntohs(ip->ip6_plen) + 40;

    return 0;
}

int
flush_flow_cb(flowtable_t *ft, flowtable_entry_t *e)
{
    switch ( e->flow.etype ) {
    case 0x0800:
        /* IPv4 */
        printf("%d.%d.%d.%d:%d->%d.%d.%d.%d:%d\n",
               e->flow.classifier.ipv4.sip.b[0],
               e->flow.classifier.ipv4.sip.b[1],
               e->flow.classifier.ipv4.sip.b[2],
               e->flow.classifier.ipv4.sip.b[3],
               e->flow.classifier.ipv4.sport,
               e->flow.classifier.ipv4.dip.b[0],
               e->flow.classifier.ipv4.dip.b[1],
               e->flow.classifier.ipv4.dip.b[2],
               e->flow.classifier.ipv4.dip.b[3],
               e->flow.classifier.ipv4.dport);
        break;
    case 0x86dd:
        /* IPv6 */
        printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x"
               ":%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
               e->flow.classifier.ipv6.sip.b[0],
               e->flow.classifier.ipv6.sip.b[1],
               e->flow.classifier.ipv6.sip.b[2],
               e->flow.classifier.ipv6.sip.b[3],
               e->flow.classifier.ipv6.sip.b[4],
               e->flow.classifier.ipv6.sip.b[5],
               e->flow.classifier.ipv6.sip.b[6],
               e->flow.classifier.ipv6.sip.b[7],
               e->flow.classifier.ipv6.sip.b[8],
               e->flow.classifier.ipv6.sip.b[9],
               e->flow.classifier.ipv6.sip.b[10],
               e->flow.classifier.ipv6.sip.b[11],
               e->flow.classifier.ipv6.sip.b[12],
               e->flow.classifier.ipv6.sip.b[13],
               e->flow.classifier.ipv6.sip.b[14],
               e->flow.classifier.ipv6.sip.b[15]);
        break;
    }
    printf("  %llu-%llu %llu %llu\n", e->stat.start_usec, e->stat.end_usec,
           e->stat.packets, e->stat.octets);
    fflush(stdout);

    return 0;
}

int
flush(flowtable_t *ft)
{
    flowtable_scan_cb(ft, flush_flow_cb);
    flowtable_reset(ft);

    return 0;
}

/*
 * Analyze packet
 */
int
analyze(struct fexporter *fexprt, struct timeval ts, const uint8_t *pkt,
        size_t caplen, size_t len)
{
    struct ether_header *eth;
    int ret;
    uint64_t curus;

    /* Flush if reaching timeout */
    curus = ts.tv_sec * 1000000 + ts.tv_usec;
    if ( fexprt->last_flushed + (uint64_t)fexprt->timeout * 1000000
         < curus ) {
        /* Flush */
        flush(fexprt->ft);
        fexprt->last_flushed = curus;
    }

    /* Ethernet header */
    eth = (struct ether_header *)pkt;
    if ( caplen < sizeof(struct ether_header) ) {
        /* Captured length is not sufficient to get the Ethernet header. */
        return -1;
    }

    switch ( ntohs(eth->ether_type) ) {
    case 0x0800:
        /* IPv4 */
        ret = analyze_ipv4(fexprt, ts, pkt + sizeof(struct ether_header),
                           caplen - sizeof(struct ether_header),
                           len - sizeof(struct ether_header), len);
        break;
    case 0x86dd:
        /* IPv6 */
        ret = analyze_ipv6(fexprt, ts, pkt + sizeof(struct ether_header),
                           caplen - sizeof(struct ether_header),
                           len - sizeof(struct ether_header), len);
        break;
    default:
        /* Others; ignore */
        ret = 0;
    }

    return ret;
}

/*
 * Callback function called from pcap_loop
 */
void
cb_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct fexporter *fexprt;
    struct timeval ts;
    size_t len;
    size_t caplen;

    /* Type conversion */
    fexprt = (struct fexporter *)user;

    ts = h->ts;
    len = h->len;
    caplen = h->caplen;

    /* Analyze this packet */
    (void)analyze(fexprt, ts, bytes, caplen, len);
}

/*
 * Main routine
 */
int
main(int argc, const char *const argv[])
{
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *ifname;
    struct bpf_program bpfp;
    /* Definition of the loopback function */
    void cb_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
    struct fexporter fexprt;

    if ( argc < 2 ) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    ifname = argv[1];

    /* Open pcap */
    pd = pcap_open_live(ifname, FEXPORTER_SNAPLEN, FEXPORTER_PROMISC,
                        FEXPORTER_TO_MS, errbuf);
    if ( NULL == pd ) {
        /* error */
        fprintf(stderr, "%s\n", errbuf);
        return EXIT_FAILURE;
    }

    /* Check the linktype */
    if ( DLT_EN10MB != pcap_datalink(pd) ) {
        fprintf(stderr, "Unsupported link type: %d\n", pcap_datalink(pd));
        pcap_close(pd);
        return EXIT_FAILURE;
    }

    /* Compile the filter (not used) */
    if ( pcap_compile(pd, &bpfp, "", 0, (bpf_u_int32)0) < 0 ) {
        /* error */
        pcap_perror(pd, "pcap_compile()");
        pcap_close(pd);
        return EXIT_FAILURE;
    }

    /* Set the compiled filter */
    if ( pcap_setfilter(pd, &bpfp) < 0 ) {
        /* error */
        pcap_perror(pd, "pcap_setfilter()");
        pcap_freecode(&bpfp);
        pcap_close(pd);
        return EXIT_FAILURE;
    }

    /* Allocate a flow table */
    fexprt.ft = flowtable_init(FEXPORTER_FLOWTABLE_SIZE);
    if ( NULL == fexprt.ft ) {
        pcap_close(pd);
        return EXIT_FAILURE;
    }
    fexprt.timeout = FEXPORTER_DEFAULT_TIMEOUT;

    /* Entering the loop, reading packets */
    if ( pcap_loop(pd, 0, cb_handler, (u_char *)&fexprt) < 0 ) {
        (void)fprintf(stderr, "%s: pcap_loop: %s\n", argv[0], pcap_geterr(pd));
        pcap_freecode(&bpfp);
        pcap_close(pd);
        flowtable_release(fexprt.ft);
        return EXIT_FAILURE;
    }

    /* Close pcap */
    pcap_freecode(&bpfp);
    pcap_close(pd);
    flowtable_release(fexprt.ft);

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
