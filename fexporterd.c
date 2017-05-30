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
#include <sys/time.h>
#include <pcap/pcap.h>

#define FEXPORTER_SNAPLEN       96
#define FEXPORTER_PROMISC       1
#define FEXPORTER_TO_MS         1


struct ipfix_template_v4 {
    int cnt;
};

struct flow_stat {
};
struct flow_classifier_ipv4 {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
};
struct flow_classifier_ipv6 {
    uint8_t sip[16];
    uint8_t dip[16];
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
};


/* Prototype declarations */
void usage(const char *);
void cb_handler(u_char *, const struct pcap_pkthdr *, const u_char *);


/*
 * Print out usage
 */
void
usage(const char *prog)
{
    fprintf(stderr, "%s: interface\n", prog);
}

/*
 * Callback function called from pcap_loop
 */
void
cb_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct timeval ts;
    size_t len;
    size_t caplen;

    len = h->len;
    caplen = h->caplen;
    //ts = h->ts;
    //h->caplen;
    //h->len;

    ts = h->ts;

    printf("%ld.%06u %zu %zu\n", ts.tv_sec, ts.tv_usec, len, caplen);
    fflush(stdout);
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

    /* Entering the loop, reading packets */
    if ( pcap_loop(pd, 0, cb_handler, (u_char *)NULL) < 0 ) {
        (void)fprintf(stderr, "%s: pcap_loop: %s\n", argv[0], pcap_geterr(pd));
        pcap_freecode(&bpfp);
        pcap_close(pd);
        return EXIT_FAILURE;
    }

    /* Close pcap */
    pcap_freecode(&bpfp);
    pcap_close(pd);

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
