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

#ifndef _FLOW_H
#define _FLOW_H

#include <stdint.h>

/*
 * IPv4 address
 */
typedef union {
    /* Byte */
    uint8_t b[4];
    /* Double-word */
    uint32_t dw;
} flow_ipv4_addr_t;

/*
 * IPv6 address
 */
typedef union {
    /* Byte */
    uint8_t b[16];
    /* Quad-words */
    uint64_t qw[2];
} flow_ipv6_addr_t;

/*
 * IPv4 flow
 */
typedef struct {
    flow_ipv4_addr_t sip;
    flow_ipv4_addr_t dip;
    uint8_t proto;
    uint16_t sport;             /* ICMP type for ICMP */
    uint16_t dport;             /* ICMP code for ICMP */
    uint8_t tos;
} flow_ipv4_t;

/*
 * IPv6 flow
 */
typedef struct {
    flow_ipv6_addr_t sip;
    flow_ipv6_addr_t dip;
    uint8_t proto;
    uint16_t sport;             /* ICMP type for ICMP */
    uint16_t dport;             /* ICMP code for ICMP */
    uint8_t tclass;             /* Traffic class */
} flow_ipv6_t;

typedef struct {
    /* Interface index */
    int ifindex;
    /* EtherType */
    uint16_t etype;
    /* Classifier */
    union {
        flow_ipv4_t ipv4;
        flow_ipv6_t ipv6;
    } classifier;
} flow_t;

/* Statistical values */
typedef struct {
    uint64_t start_usec;
    uint64_t end_usec;
    uint64_t octets;
    uint64_t packets;
} flow_stats_t;

#endif /* _FLOW_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
