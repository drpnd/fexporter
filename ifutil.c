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

#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#ifndef SIOCGIFHWADDR
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif

/*
 * Get MAC address
 */
int
ifutil_macaddr(const char *ifname, uint8_t *macaddr)
{
#ifndef SIOCGIFHWADDR
    int ret;
    struct ifaddrs *ifs;
    struct ifaddrs *cursor;
    struct sockaddr_dl *dladdr;
    unsigned char *base;

    ret = getifaddrs(&ifs);
    if ( 0 != ret ) {
        return -1;
    }

    cursor = ifs;
    while ( NULL != cursor ) {
        if ( 0 == strcmp(ifname, cursor->ifa_name) ) {
            if ( AF_LINK == cursor->ifa_addr->sa_family ) {
                dladdr = (struct sockaddr_dl *)cursor->ifa_addr;
                base = (unsigned char *)&dladdr->sdl_data[dladdr->sdl_nlen];
                if ( 6 != dladdr->sdl_alen ) {
                    return -1;
                }
                memcpy(macaddr, base, dladdr->sdl_alen);
                return 0;
            }
        }
        cursor = cursor->ifa_next;
    }
#else
    struct ifconf ifconf;
    int sock;
    char buf[1024];
    int ret;
    struct ifreq ifreq;
    struct ifreq *ifcur;
    ssize_t i;
    size_t len;

    /* Issue SIOCGIFCONF ioctl */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if ( sock < 0 ) {
        return -1;
    }

#if 0
    /* All interfaces */
    ifconf.ifc_len = sizeof(buf);
    ifconf.ifc_buf = buf;
    ret = ioctl(sock, SIOCGIFCONF, &ifconf);
    if ( ret < 0 ) {
        close(sock);
        return -1;
    }

    ifcur = ifconf.ifc_req;
    len = ifconf.ifc_len / sizeof(struct ifreq);
    for ( i = 0; i < (ssize_t)len; i++ ) {
        //ifcur[i];
    }
#endif

    strcpy(ifreq.ifr_name, ifname);
    if ( 0 == ioctl(sock, SIOCGIFFLAGS, &ifreq) ) {
        if ( 0 == ioctl(sock, SIOCGIFHWADDR, &ifreq) ) {
            memcpy(macaddr, ifreq.ifr_hwaddr.sa_data, 6);
            return 0;
        }
    }
#endif

    return -1;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
