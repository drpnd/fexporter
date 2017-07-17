/*_
 * Copyright (c) 2009, 2017 Hirochika Asai <asai@jar.jp>
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

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/signal.h>
#include <unistd.h>

/*
 * Daemonize this process
 */
int
ng_daemon(int nochdir, int noclose)
{
    struct sigaction osa, sa;
    int fd;
    pid_t newgrp;
    int oerrno;
    int osa_ok;

    /* A SIGHUP may be thrown when the parent exits below. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    osa_ok = sigaction(SIGHUP, &sa, &osa);

    switch ( fork() ) {
    case -1:
        return -1;
    case 0:
        break;
    default:
        exit(0);
    }

    newgrp = setsid();
    oerrno = errno;
    if ( -1 != osa_ok ) {
        sigaction(SIGHUP, &osa, NULL);
    }

    if ( -1 == newgrp ) {
        errno = oerrno;
        return -1;
    }

    if ( !nochdir ) {
        (void)chdir("/");
    }

    if ( !noclose ) {
        fd = open(_PATH_DEVNULL, O_RDWR, 0);
        if ( -1 != fd ) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if ( fd > 2 ) {
                (void)close(fd);
            }
        }
    }

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
