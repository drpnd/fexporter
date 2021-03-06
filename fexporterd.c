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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ipfix.h"
#include "flowtable.h"
#include "ifutil.h"

/* # of entries in the flow table */
#define FEXPORTER_FLOWTABLE_SIZE 2048

/* Default timeout in seconds */
#define FEXPORTER_DEFAULT_TIMEOUT 300

#define FEXPORTER_SNAPLEN       96
#define FEXPORTER_PROMISC       1
#define FEXPORTER_TO_MS         1

#define FEXPORTER_IPV4_ID       259
#define FEXPORTER_IPV4_OBS      256
#define FEXPORTER_IPV6_ID       260
#define FEXPORTER_IPV6_OBS      512

/*
 * Options
 */
struct fexporter_config {
    int family;
    char *ifname;
    char *host;
    uint16_t port;
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
    /* MAC address to determine the direction */
    uint8_t macaddr[6];

    /* Flowseq for IPv4 */
    uint32_t seq4;
    /* Flowseq for IPv6 */
    uint32_t seq6;

    /* Socket */
    int sock;
    struct sockaddr_storage saddr;

    /* Config */
    struct fexporter_config cfg;
};


/* Prototype declarations */
void usage(const char *);
uint64_t diff_timeval(struct timeval, struct timeval);
void cb_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int flush(struct fexporter *);

#if !defined(ntohll)
static __inline__ uint64_t
ntohll(uint64_t a)
{
#ifdef WORDS_BIGENDIAN
    return a;
#else
    uint32_t lo = a & 0xffffffff;
    uint32_t hi = a >> 32U;
    lo = ntohl(lo);
    hi = ntohl(hi);
    return ((uint64_t) lo) << 32U | hi;
#endif
}
#endif

#if !defined(htonll)
static __inline__ uint64_t
htonll(uint64_t a)
{
#ifdef WORDS_BIGENDIAN
    return a;
#else
    uint32_t lo = a & 0xffffffff;
    uint32_t hi = a >> 32U;
    lo = ntohl(lo);
    hi = ntohl(hi);
    return ((uint64_t) lo) << 32U | hi;
#endif
}
#endif

/*
 * Print out usage
 */
void
usage(const char *prog)
{
    fprintf(stderr, "%s: <agent-ipaddr> <port> <interface>\n", prog);
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
 * Generate flow template set for IPv4 flows
 */
ssize_t
flow_template_set_v4(uint8_t *pkt)
{
    struct ipfix_set_header *hdr;
    struct ipfix_template_header *tmpl;
    struct ipfix_template_field *field;
    int n;

    hdr = (struct ipfix_set_header *)pkt;
    hdr->id = htons(templateSet);

    tmpl = (struct ipfix_template_header *)(hdr + 1);
    tmpl->template_id = htons(FEXPORTER_IPV4_ID);

    field = (struct ipfix_template_field *)(tmpl + 1);
    n = 0;

    /* IPv4 source address */
    field[n].type = htons(sourceIPv4Address);
    field[n].length = htons(4);
    n++;

    /* IPv4 destination address */
    field[n].type = htons(destinationIPv4Address);
    field[n].length = htons(4);
    n++;

    /* IP protocol version */
    field[n].type = htons(ipVersion);
    field[n].length = htons(1);
    n++;

    /* Protocol */
    field[n].type = htons(protocolIdentifier);
    field[n].length = htons(1);
    n++;

    /* Source port */
    field[n].type = htons(sourceTransportPort);
    field[n].length = htons(2);
    n++;

    /* Destination port */
    field[n].type = htons(destinationTransportPort);
    field[n].length = htons(2);
    n++;

    /* ICMP type */
    field[n].type = htons(icmpTypeIPv4);
    field[n].length = htons(1);
    n++;

    /* ICMP code */
    field[n].type = htons(icmpCodeIPv4);
    field[n].length = htons(1);
    n++;

    /* Flow direction */
    field[n].type = htons(flowDirection);
    field[n].length = htons(1);
    n++;

    /* Interfaces */
    field[n].type = htons(ingressInterface);
    field[n].length = htons(4);
    n++;
    field[n].type = htons(egressInterface);
    field[n].length = htons(4);
    n++;


    /* Bytes */
    field[n].type = htons(octetDeltaCount);
    field[n].length = htons(8);
    n++;

    /* Packets */
    field[n].type = htons(packetDeltaCount);
    field[n].length = htons(8);
    n++;

    /* Start */
    field[n].type = htons(flowStartMilliseconds);
    field[n].length = htons(8);
    n++;

    /* End */
    field[n].type = htons(flowEndMilliseconds);
    field[n].length = htons(8);
    n++;

    tmpl->field_count = htons(n);
    uint16_t length = (void *)&field[n] - (void *)hdr;
    hdr->length = htons(length);

    return length;
}

/*
 * Build flow for IPv4 flows
 */
ssize_t
flow_v4(flow_t *flow, flow_stats_t *stats, uint8_t *pkt)
{
    int n;

    n = 0;

    /* IPv4 source address */
    memcpy(pkt + n, flow->classifier.ipv4.sip.b, 4);
    n += 4;

    /* IPv4 destination address */
    memcpy(pkt + n, flow->classifier.ipv4.dip.b, 4);
    n += 4;

    /* IP protocol version */
    *(pkt + n) = 4;
    n++;

    /* Protocol */
    *(pkt + n) = flow->classifier.ipv4.proto;
    n++;

    if ( 1 == flow->classifier.ipv4.proto ) {
        /* ICMP */
        /* Source port */
        *(uint16_t *)(pkt + n) = 0;
        n += 2;

        /* Destination port */
        *(uint16_t *)(pkt + n) = 0;
        n += 2;

        /* ICMP type */
        *(pkt + n) = flow->classifier.ipv4.sport;
        n++;

        /* ICMP code */
        *(pkt + n) = flow->classifier.ipv4.dport;
        n++;
    } else {
        /* TCP/UDP */
        /* Source port */
        *(uint16_t *)(pkt + n) = htons(flow->classifier.ipv4.sport);
        n += 2;

        /* Destination port */
        *(uint16_t *)(pkt + n) = htons(flow->classifier.ipv4.dport);
        n += 2;

        /* ICMP type */
        *(pkt + n) = 0;
        n++;

        /* ICMP code */
        *(pkt + n) = 0;
        n++;
    }

    /* Direction */
    *(uint8_t *)(pkt + n) = flow->direction;
    n++;

    /* Interface */
    if ( flow->direction ) {
        /* Egress */
        *(uint32_t *)(pkt + n) = htonl(0);
        n += 4;
        *(uint32_t *)(pkt + n) = htonl(1);
        n += 4;
    } else {
        /* Ingress */
        *(uint32_t *)(pkt + n) = htonl(1);
        n += 4;
        *(uint32_t *)(pkt + n) = htonl(0);
        n += 4;
    }

    /* Bytes */
    *(uint64_t *)(pkt + n) = htonll(stats->octets);
    n += 8;

    /* Packets */
    *(uint64_t *)(pkt + n) = htonll(stats->packets);
    n += 8;

    /* Start */
    *(uint64_t *)(pkt + n) = htonll(stats->start_msec);
    n += 8;

    /* End */
    *(uint64_t *)(pkt + n) = htonll(stats->end_msec);
    n += 8;

    return n;
}

/*
 * Generate flow template set for IPv4 flows
 */
ssize_t
flow_template_set_v6(uint8_t *pkt)
{
    struct ipfix_set_header *hdr;
    struct ipfix_template_header *tmpl;
    struct ipfix_template_field *field;
    int n;

    hdr = (struct ipfix_set_header *)pkt;
    hdr->id = htons(templateSet);

    tmpl = (struct ipfix_template_header *)(hdr + 1);
    tmpl->template_id = htons(FEXPORTER_IPV6_ID);

    field = (struct ipfix_template_field *)(tmpl + 1);
    n = 0;

    /* IPv6 source address */
    field[n].type = htons(sourceIPv6Address);
    field[n].length = htons(16);
    n++;

    /* IPv6 destination address */
    field[n].type = htons(destinationIPv6Address);
    field[n].length = htons(16);
    n++;

    /* IP protocol version */
    field[n].type = htons(ipVersion);
    field[n].length = htons(1);
    n++;

    /* Protocol */
    field[n].type = htons(protocolIdentifier);
    field[n].length = htons(1);
    n++;

    /* Source port */
    field[n].type = htons(sourceTransportPort);
    field[n].length = htons(2);
    n++;

    /* Destination port */
    field[n].type = htons(destinationTransportPort);
    field[n].length = htons(2);
    n++;

    /* ICMPv6 type */
    field[n].type = htons(icmpTypeIPv6);
    field[n].length = htons(1);
    n++;

    /* ICMPv6 code */
    field[n].type = htons(icmpCodeIPv6);
    field[n].length = htons(1);
    n++;

    /* Flow direction */
    field[n].type = htons(flowDirection);
    field[n].length = htons(1);
    n++;

    /* Interfaces */
    field[n].type = htons(ingressInterface);
    field[n].length = htons(4);
    n++;
    field[n].type = htons(egressInterface);
    field[n].length = htons(4);
    n++;

    /* Bytes */
    field[n].type = htons(octetDeltaCount);
    field[n].length = htons(8);
    n++;

    /* Packets */
    field[n].type = htons(packetDeltaCount);
    field[n].length = htons(8);
    n++;

    /* Start */
    field[n].type = htons(flowStartMilliseconds);
    field[n].length = htons(8);
    n++;

    /* End */
    field[n].type = htons(flowEndMilliseconds);
    field[n].length = htons(8);
    n++;

    tmpl->field_count = htons(n);
    uint16_t length;
    length = (void *)&field[n] - (void *)hdr;
    hdr->length = htons(length);

    return length;
}

/*
 * Build flow for IPv6 flows
 */
ssize_t
flow_v6(flow_t *flow, flow_stats_t *stats, uint8_t *pkt)
{
    int n;

    n = 0;

    /* IPv6 source address */
    memcpy(pkt + n, flow->classifier.ipv6.sip.b, 16);
    n += 16;

    /* IPv4 destination address */
    memcpy(pkt + n, flow->classifier.ipv6.dip.b, 16);
    n += 16;

    /* IP protocol version */
    *(pkt + n) = 6;
    n++;

    /* Protocol */
    *(pkt + n) = flow->classifier.ipv6.proto;
    n++;

    if ( 58 == flow->classifier.ipv6.proto ) {
        /* ICMPv6 */
        /* Source port */
        *(uint16_t *)(pkt + n) = 0;
        n += 2;

        /* Destination port */
        *(uint16_t *)(pkt + n) = 0;
        n += 2;

        /* ICMP type */
        *(pkt + n) = flow->classifier.ipv6.sport;
        n++;

        /* ICMP code */
        *(pkt + n) = flow->classifier.ipv6.dport;
        n++;
    } else {
        /* TCP/UDP */
        /* Source port */
        *(uint16_t *)(pkt + n) = htons(flow->classifier.ipv6.sport);
        n += 2;

        /* Destination port */
        *(uint16_t *)(pkt + n) = htons(flow->classifier.ipv6.dport);
        n += 2;

        /* ICMP type */
        *(pkt + n) = 0;
        n++;

        /* ICMP code */
        *(pkt + n) = 0;
        n++;
    }

    /* Direction */
    *(uint8_t *)(pkt + n) = flow->direction;
    n++;

    /* Interface */
    if ( flow->direction ) {
        /* Egress */
        *(uint32_t *)(pkt + n) = htonl(0);
        n += 4;
        *(uint32_t *)(pkt + n) = htonl(1);
        n += 4;
    } else {
        /* Ingress */
        *(uint32_t *)(pkt + n) = htonl(1);
        n += 4;
        *(uint32_t *)(pkt + n) = htonl(0);
        n += 4;
    }

    /* Bytes */
    *(uint64_t *)(pkt + n) = htonll(stats->octets);
    n += 8;

    /* Packets */
    *(uint64_t *)(pkt + n) = htonll(stats->packets);
    n += 8;

    /* Start */
    *(uint64_t *)(pkt + n) = htonll(stats->start_msec);
    n += 8;

    /* End */
    *(uint64_t *)(pkt + n) = htonll(stats->end_msec);
    n += 8;

    return n;
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
analyze_icmpv6(const uint8_t *pkt, size_t caplen, uint16_t *type,
               uint16_t *code)
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
    *sport = ntohs(tcp->th_sport);
    *dport = ntohs(tcp->th_dport);

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
    *sport = ntohs(udp->uh_sport);
    *dport = ntohs(udp->uh_dport);

    return 0;
}

/*
 * Analyze IPv4 packet
 */
int
analyze_ipv4(struct fexporter *fexprt, struct timeval ts, const uint8_t *pkt,
             size_t caplen, size_t len, size_t origlen, int dir)
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
    flow.direction = dir;
    flow.etype = 0x0800;
    flow.classifier.ipv4.sip.dw = ip->ip_src.s_addr;
    flow.classifier.ipv4.dip.dw = ip->ip_dst.s_addr;
    flow.classifier.ipv4.proto = proto;
    flow.classifier.ipv4.sport = sport;
    flow.classifier.ipv4.dport = dport;

    /* Update statistics */
    stats = flowtable_search(fexprt->ft, &flow);
    if ( NULL == stats  ) {
        flush(fexprt);
        stats = flowtable_search(fexprt->ft, &flow);
        if ( NULL == stats  ) {
            return -1;
        }
    }
    if ( !stats->start_msec ) {
        stats->start_msec = ts.tv_sec * 1000 + ts.tv_usec / 1000;
    }
    stats->end_msec = ts.tv_sec * 1000 + ts.tv_usec / 1000;
    stats->packets += 1;
    stats->octets += ntohs(ip->ip_len);

    return 0;
}

/*
 * Analyze IPv6 packet
 */
int
analyze_ipv6(struct fexporter *fexprt, struct timeval ts, const uint8_t *pkt,
             size_t caplen, size_t len, size_t origlen, int dir)
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
    flow.direction = dir;
    flow.etype = 0x86dd;
    memcpy(flow.classifier.ipv6.sip.b, ip->ip6_src.s6_addr, 16);
    memcpy(flow.classifier.ipv6.dip.b, ip->ip6_dst.s6_addr, 16);
    flow.classifier.ipv6.proto = proto;
    flow.classifier.ipv6.sport = sport;
    flow.classifier.ipv6.dport = dport;

    /* Update statistics */
    stats = flowtable_search(fexprt->ft, &flow);
    if ( NULL == stats  ) {
        flush(fexprt);
        stats = flowtable_search(fexprt->ft, &flow);
        if ( NULL == stats  ) {
            return -1;
        }
    }
    if ( !stats->start_msec ) {
        stats->start_msec = ts.tv_sec * 1000 + ts.tv_usec / 1000;
    }
    stats->end_msec = ts.tv_sec * 1000 + ts.tv_usec / 1000;
    stats->packets += 1;
    stats->octets += ntohs(ip->ip6_plen) + 40;

    return 0;
}

/*
 * Export IPv4 flows
 */
int
export_ipv4_flows(struct fexporter *fexprt, flow_t *flow, flow_stats_t *stats,
                  struct timeval ts)
{
    uint8_t pkt[1500];
    ssize_t len;
    int ret;
    struct ipfix_header *ipfix;
    struct ipfix_set_header *hdr;

    /* IPv4 */
    ipfix = (struct ipfix_header *)pkt;
    ipfix->version = htons(10);
    ipfix->timestamp = htonl(ts.tv_sec);
    ipfix->flowseq = htonl(fexprt->seq4);
    ipfix->obs_dom_id = htonl(FEXPORTER_IPV4_OBS);
    hdr = (struct ipfix_set_header *)(ipfix + 1);
    hdr->id = htons(FEXPORTER_IPV4_ID);
    len = flow_v4(flow, stats, (uint8_t *)(hdr + 1));
    if ( len < 0 ) {
        return -1;
    }
    len = len + sizeof(struct ipfix_set_header);
    hdr->length = htons(len);
    len = len + sizeof(struct ipfix_header);
    ipfix->length = htons(len);
    if ( fexprt->saddr.ss_family == AF_INET ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in));
        if ( ret < 0 ) {
            return -1;
        }
    } else if ( fexprt->saddr.ss_family == AF_INET6 ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in6));
        if ( ret < 0 ) {
            return -1;
        }
    }
    fexprt->seq4++;

    return 0;
}

/*
 * Export IPv6 flows
 */
int
export_ipv6_flows(struct fexporter *fexprt, flow_t *flow, flow_stats_t *stats,
                  struct timeval ts)
{
    uint8_t pkt[1500];
    ssize_t len;
    int ret;
    struct ipfix_header *ipfix;
    struct ipfix_set_header *hdr;

    /* IPv4 */
    ipfix = (struct ipfix_header *)pkt;
    ipfix->version = htons(10);
    ipfix->timestamp = htonl(ts.tv_sec);
    ipfix->flowseq = htonl(fexprt->seq6);
    ipfix->obs_dom_id = htonl(FEXPORTER_IPV6_OBS);
    hdr = (struct ipfix_set_header *)(ipfix + 1);
    hdr->id = htons(FEXPORTER_IPV6_ID);
    len = flow_v6(flow, stats, (uint8_t *)(hdr + 1));
    if ( len < 0 ) {
        return -1;
    }
    len = len + sizeof(struct ipfix_set_header);
    hdr->length = htons(len);
    len = len + sizeof(struct ipfix_header);
    ipfix->length = htons(len);
    if ( fexprt->saddr.ss_family == AF_INET ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in));
        if ( ret < 0 ) {
            return -1;
        }
    } else if ( fexprt->saddr.ss_family == AF_INET6 ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in6));
        if ( ret < 0 ) {
            return -1;
        }
    }
    fexprt->seq6++;

    return 0;
}

/*
 * Callback function to export a flow
 */
int
flush_flow_cb(flowtable_t *ft, flowtable_entry_t *e, void *user)
{
    struct fexporter *fexprt;
    struct timeval ts;

    fexprt = (struct fexporter *)user;

    gettimeofday(&ts, NULL);

    switch ( e->flow.etype ) {
    case 0x0800:
        /* IPv4 */
        export_ipv4_flows(fexprt, &e->flow, &e->stat, ts);
        break;
    case 0x86dd:
        /* IPv6 */
        export_ipv6_flows(fexprt, &e->flow, &e->stat, ts);
        break;
    }

    return 0;
}

/*
 * Flush flow
 */
int
flush(struct fexporter *fexprt)
{
    flowtable_scan_cb(fexprt->ft, flush_flow_cb, fexprt);
    flowtable_reset(fexprt->ft);

    return 0;
}

/*
 * Export template
 */
int
export_template(struct fexporter *fexprt, struct timeval ts)
{
    uint8_t pkt[1500];
    ssize_t len;
    int ret;
    struct ipfix_header *ipfix;

    /* IPv4 */
    ipfix = (struct ipfix_header *)pkt;
    ipfix->version = htons(10);
    ipfix->timestamp = htonl(ts.tv_sec);
    ipfix->flowseq = htonl(fexprt->seq4);
    ipfix->obs_dom_id = htonl(FEXPORTER_IPV4_OBS);
    len = flow_template_set_v4((uint8_t *)(ipfix + 1));
    if ( len < 0 ) {
        return -1;
    }
    len = len + sizeof(struct ipfix_header);
    ipfix->length = htons(len);
    if ( fexprt->saddr.ss_family == AF_INET ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in));
        if ( ret < 0 ) {
            return -1;
        }
    } else if ( fexprt->saddr.ss_family == AF_INET6 ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in6));
        if ( ret < 0 ) {
            return -1;
        }
    }

    /* IPv6 */
    ipfix = (struct ipfix_header *)pkt;
    ipfix->version = htons(10);
    ipfix->timestamp = htonl(ts.tv_sec);
    ipfix->flowseq = htonl(fexprt->seq6);
    ipfix->obs_dom_id = htonl(FEXPORTER_IPV6_OBS);
    len = flow_template_set_v6((uint8_t *)(ipfix + 1));
    if ( len < 0 ) {
        return -1;
    }
    len = len + sizeof(struct ipfix_header);
    ipfix->length = htons(len);
    if ( fexprt->saddr.ss_family == AF_INET ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in));
        if ( ret < 0 ) {
            return -1;
        }
    } else if ( fexprt->saddr.ss_family == AF_INET6 ) {
        ret = sendto(fexprt->sock, pkt, len, 0,
                     (struct sockaddr *)&fexprt->saddr,
                     sizeof(struct sockaddr_in6));
        if ( ret < 0 ) {
            return -1;
        }
    }

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
    int dir;

    /* Flush if reaching timeout */
    curus = ts.tv_sec * 1000000 + ts.tv_usec;
    if ( fexprt->last_flushed + (uint64_t)fexprt->timeout * 1000000
         < curus ) {
        /* Export template */
        export_template(fexprt, ts);

        /* Flush */
        flush(fexprt);

        /* Update timestamp */
        fexprt->last_flushed = curus;
    }

    /* Ethernet header */
    eth = (struct ether_header *)pkt;
    if ( caplen < sizeof(struct ether_header) ) {
        /* Captured length is not sufficient to get the Ethernet header. */
        return -1;
    }
    /* Determine the direction from the MAC address */
    if ( 0 == memcmp(eth->ether_shost, fexprt->macaddr, 6) ) {
        /* Egress */
        dir = 1;
    } else {
        /* Ingress */
        dir = 0;
    }

    switch ( ntohs(eth->ether_type) ) {
    case 0x0800:
        /* IPv4 */
        ret = analyze_ipv4(fexprt, ts, pkt + sizeof(struct ether_header),
                           caplen - sizeof(struct ether_header),
                           len - sizeof(struct ether_header), len, dir);
        break;
    case 0x86dd:
        /* IPv6 */
        ret = analyze_ipv6(fexprt, ts, pkt + sizeof(struct ether_header),
                           caplen - sizeof(struct ether_header),
                           len - sizeof(struct ether_header), len, dir);
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
 * Parse options
 */
int
parse_opts(int argc, const char *const argv[], struct fexporter_config *cfg)
{
    const char *s;
    const char *host;
    const char *port;

    if ( argc < 4 ) {
        return -1;
    }

    /* Host */
    host = argv[1];

    /* Family */
    cfg->family = AF_INET;
    s = host;
    while ( *s ) {
        if ( ':' == *s ) {
            cfg->family = AF_INET6;
            break;
        }
        s++;
    }

    /* Port */
    port = argv[2];

    if ( NULL == port || 0 == strcmp("", port) ) {
        /* Port is not specified */
        cfg->port = 9996;
        cfg->host = strdup(host);
        if ( NULL == cfg->host ) {
            return -1;
        }
    } else {
        /* Port is specified */
        cfg->host = strdup(host);
        cfg->port = atoi(port);
    }

    /* Interface */
    cfg->ifname = strdup(argv[3]);
    if ( NULL == cfg->ifname ) {
        free(cfg->host);
        return -1;
    }

    return 0;
}

/*
 * Main routine
 */
int
main(int argc, const char *const argv[])
{
    pcap_t *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpfp;
    /* Definition of the loopback function */
    void cb_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
    struct fexporter fexprt;
    int ret;

    /* Parse the configuration */
    ret = parse_opts(argc, argv, &fexprt.cfg);
    if ( ret < 0 ) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Open pcap */
    pd = pcap_open_live(fexprt.cfg.ifname, FEXPORTER_SNAPLEN, FEXPORTER_PROMISC,
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

    /* Get local MAC address */
    if ( ifutil_macaddr(fexprt.cfg.ifname, fexprt.macaddr) < 0 ) {
        pcap_close(pd);
        flowtable_release(fexprt.ft);
        return EXIT_FAILURE;
    }


    memset(&fexprt.saddr, 0, sizeof(struct sockaddr_storage));
    if ( AF_INET == fexprt.cfg.family ) {
        /* Open UDP socket for IPv4 */
        fexprt.sock = socket(AF_INET, SOCK_DGRAM, 0);
        if ( fexprt.sock < 0 ) {
            fprintf(stderr, "Cannot open a UDP socket.");
            pcap_freecode(&bpfp);
            pcap_close(pd);
            flowtable_release(fexprt.ft);
            return EXIT_FAILURE;
        }
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in *)&fexprt.saddr;
        sin->sin_family = fexprt.cfg.family;
        sin->sin_port = htons(fexprt.cfg.port);
        ret = inet_pton(fexprt.cfg.family, fexprt.cfg.host, &sin->sin_addr);
    } else if ( AF_INET6 == fexprt.cfg.family ) {
        /* Open UDP socket for IPv6 */
        fexprt.sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if ( fexprt.sock < 0 ) {
            fprintf(stderr, "Cannot open a UDP socket.");
            pcap_freecode(&bpfp);
            pcap_close(pd);
            flowtable_release(fexprt.ft);
            return EXIT_FAILURE;
        }
        struct sockaddr_in6 *sin;
        sin = (struct sockaddr_in6 *)&fexprt.saddr;
        sin->sin6_family = fexprt.cfg.family;
        sin->sin6_port = htons(fexprt.cfg.port);
        ret = inet_pton(fexprt.cfg.family, fexprt.cfg.host, &sin->sin6_addr);
    } else {
        close(fexprt.sock);
        pcap_freecode(&bpfp);
        pcap_close(pd);
        flowtable_release(fexprt.ft);
        return EXIT_FAILURE;
    }
    if ( 1 != ret ) {
        close(fexprt.sock);
        pcap_freecode(&bpfp);
        pcap_close(pd);
        flowtable_release(fexprt.ft);
        return EXIT_FAILURE;
    }

    /* Entering the loop, reading packets */
    if ( pcap_loop(pd, 0, cb_handler, (u_char *)&fexprt) < 0 ) {
        (void)fprintf(stderr, "%s: pcap_loop: %s\n", argv[0], pcap_geterr(pd));
        pcap_freecode(&bpfp);
        pcap_close(pd);
        flowtable_release(fexprt.ft);
        close(fexprt.sock);
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
