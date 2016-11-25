/*
 * Part of Hashcash Milter version 0.1.3 from <http://althenia.net/hashcash>.
 *
 * Copyright 2010 Andrey Zholos.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "util.h"

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <libmilter/mfapi.h>

extern struct ipaddr* cover_ipaddrs;
extern struct string* cover_domains;
extern int random_fd;

sfsistat hcfi_connect(SMFICTX* ctx, char* hostname, _SOCK_ADDR* hostaddr);
sfsistat hcfi_envfrom(SMFICTX* ctx, char** argv);
sfsistat hcfi_envrcpt(SMFICTX *ctx, char** argv);
sfsistat hcfi_header(SMFICTX* ctx, char* name, char* value);
sfsistat hcfi_eom(SMFICTX* ctx);
sfsistat hcfi_close(SMFICTX* ctx);


void openlog(const char* ident, int logopt, int facility) {
}

void syslog(int priority, const char* message, ...) {
    va_list args;
    va_start(args, message);
    printf("syslog(%d): ", priority);
    vprintf(message, args);
    putchar('\n');
    va_end(args);
}


time_t time(time_t* t) {
    return 1267354128;
}


int smfi_setconn(char *oconn) {
    return MI_SUCCESS;
}

int smfi_register(struct smfiDesc descr) {
    return MI_SUCCESS;
}

int smfi_opensocket(bool rmsocket) {
    return MI_SUCCESS;
}

char* symval_i = NULL;
char* symval_j = NULL;
char* symval_auth_type = NULL;

char* smfi_getsymval(SMFICTX* ctx, char* symname) {
    if (!strcasecmp(symname, "i"))
        return symval_i;
    else if (!strcasecmp(symname, "j"))
        return symval_j;
    else if (!strcasecmp(symname, "{auth_type}"))
        return symval_auth_type;
    else
        return NULL;
}

void* test_priv = NULL;

int smfi_setpriv(SMFICTX* ctx, void* privatedata) {
    test_priv = privatedata;
    return MI_SUCCESS;
}

void* smfi_getpriv(SMFICTX* ctx) {
    return test_priv;
}

int smfi_addheader(SMFICTX* ctx, char* headerf, char* headerv) {
    printf("add header: %s: %s\n", headerf, headerv);
    return MI_SUCCESS;
}

int smfi_insheader(SMFICTX* ctx, int hdridx, char* headerf, char* headerv) {
    printf("insert header at %d: %s: %s\n", hdridx, headerf, headerv);
    return MI_SUCCESS;
}

int smfi_chgheader(SMFICTX *ctx, char *headerf, int hdridx, char *headerv) {
    if (headerv == NULL)
        printf("remove instance %d of header: %s\n", hdridx, headerf);
    else
        printf("change instance %d of header: %s: %s\n",
               hdridx, headerf, headerv);
    return MI_SUCCESS;
};


char* tests[][2] = {
    /* outgoing by SMTP auth, needs one token */
    { "a",
                    "hare@forest.example" }, /* MAIL */
    { NULL,         "fox@forest.example" },  /* RCPT */
    { "From",       "Brown Hare <hare@forest.example>" },
    { "To",         "Red Fox <fox@forest.example>" },
    { "Subject",    "Test Hashcash" },
    { "Date",       "28 Feb 2010 10:48:28 +0000" },
    { NULL,         NULL },

    /* outgoing by network address, needs three tokens */
    { "192.0.2.1",
                    "<hare@forest.example>" },               /* MAIL */
    { NULL,         "<deer@forest.example>" },               /* RCPT */
    { NULL,         "<squirrel@forest.example>" },           /* RCPT */
    { NULL,         "<firebird@enchanted.forest.example>" }, /* RCPT */
    { "From",       "\"Brown Hare\" <hare@forest.example>" },
    { "To",         "\"Roe Deer\" <deer@forest.example>" },
    { "CC",         "\"Red Squirrel\" <squirrel@forest.example>, "
                    "\"Fire Bird\" <firebird@enchanted.forest.example>" },
    { NULL,         NULL },

    /* incoming, check two tokens */
    { "2001:db8::1",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "squirrel@forest.example (Red Squirrel)" },
    { "To",         "Forest creatures: \"<Red Fox>\" <fox@forest.example>, "
                    "hare@forest.example (Brown Hare);" },
    { "X-Hashcash", "1:33:100228:fox@forest.example::204CrdoQ1G2I2Jm2:1labk" },
    { "X-Hashcash", "1:24:100228:hare@forest.example::FvtQe1L2Ct8gT7u+:WIs" },
    { "X-Hashcash", "1:20:100228:hare@forest.example::e5IroF6SOb1NLlKc:/p" },
    { NULL,         NULL },

    /* incoming, check token and remove invalid auth results */
    { "2001:db8::2",
                    "<pike@river.example>" },  /* MAIL */
    { NULL,         "<hare@forest.example>" }, /* RCPT */
    { "To",         "\"hare\"@forest.example" },
    { "X-Hashcash", "1:27:100228:hare@forest.example::cLqCWUHurSkxrJLu:0LflI" },
    { "Authentication-Results", "forest.example; dkim=pass (1024-bit key)\n"
                              "\theader.i=@river.example; dkip-asp=none" },
    { "Authentication-Results", "forest.example; x-hashcash=pass (99 bits)" },
    { "Authentication-Results", "river.example; x-hashcash=pass (27 bits)" },
    { NULL,         NULL },

    /* outgoing, but skip minting */
    { "a",
                    "hare@forest.example" }, /* MAIL */
    { NULL,         "fox@forest.example" },  /* RCPT */
    { "From",       "Brown Hare <hare@forest.example>" },
    { "To",         "Red Fox <fox@forest.example>" },
    { "X-Hashcash", "1:24:100228:fox@forest.example::rBxGjWOXsCn4Qp2e:lOe" },
    { "X-Hashcash", "skip" },
    { NULL,         NULL },

    /* incoming, duplicate recipient */
    { "2001:db8::3",
                    "<fox@forest.example>" },  /* MAIL */
    { NULL,         "<hare@forest.example>" }, /* RCPT */
    { NULL,         "<hare@forest.example>" }, /* RCPT (from BCC) */
    { "From",       "Red Fox <fox@forest.example>" },
    { "To",         "Brown Hare <hare@forest.example>" },
    { "X-Hashcash", "1:24:100228:hare@forest.example::RgMtMBkqOLj3cnOG:M3P" },
    { NULL,         NULL },

    /* incoming, check for partial result with missing */
    { "2001:db8::4",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "Red Squirrel <squirrel@forest.example>" },
    { "To",         "fox@forest.example, hare@forest.example" },
    { "X-Hashcash", "1:30:100228:fox@forest.example::DYx0+BiC=NyZfDkt:xgrt" },
    { NULL,         NULL },

    /* incoming, check for partial result with policy */
    { "2001:db8::5",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "Red Squirrel <squirrel@forest.example>" },
    { "To",         "Red Fox <fox@forest.example>, "
                    "Brown Hare <hare@forest.example>" },
    { "X-Hashcash", "1:27:100228:fox@forest.example::K4JCGyvxGiJpmHNH:BJ" },
    { "X-Hashcash", "1:12:100228:fox@forest.example::MyJ6Ay0zoJrqPgmL:" },
    { NULL,         NULL },

    /* incoming, check for policy (insufficient) result */
    { "2001:db8::6",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "Red Squirrel <squirrel@forest.example>" },
    { "To",         "fox@forest.example, hare@forest.example" },
    { "X-Hashcash", "1:15:100228:hare@forest.example::abpafMRkluUz=y+o:" },
    { "X-Hashcash", "1:12:100228:fox@forest.example::t/OPw3wV/5JDw5gU:" },
    { NULL,         NULL },

    /* incoming, check for policy (futuristic) result */
    { "2001:db8::7",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "Red Squirrel <squirrel@forest.example>" },
    { "To",         "fox@forest.example, hare@forest.example" },
    { "X-Hashcash", "1:33:101104:fox@forest.example::yArxmPnXL7=sqmi0:Gj2m" },
    { NULL,         NULL },

    /* incoming, check for fail result */
    { "2001:db8::8",
                    "<squirrel@forest.example>" }, /* MAIL */
    { NULL,         "<hare@forest.example>" },     /* RCPT */
    { NULL,         "<fox@forest.example>" },      /* RCPT */
    { "From",       "Red Squirrel <squirrel@forest.example>" },
    { "To",         "fox@forest.example, hare@forest.example" },
    { "X-Hashcash", "1:44:100228:hare@forest.example:::" },
    { "X-Hashcash", "1:30:100228:fox@forest.example::CSuzvfMMSLoMelTA:awP9" },
    { NULL,         NULL },

    /* incoming, neutral result */
    { "2001:db8::9",
                    "bear@forest.example" }, /* MAIL */
    { NULL,         "hare@forest.example" }, /* RCPT */
    { "X-Hashcash", "skip" },
    { NULL,         NULL },

    { NULL,         NULL }
};

int smfi_main() {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct ipaddr* next_addr;
    int i, count, status;

    memset(&in, 0, sizeof in);
    memset(&in6, 0, sizeof in6);

    /*do
        random_fd = open("/dev/zero", O_RDONLY);
    while (random_fd == -1 && errno == EINTR);
    if (random_fd == -1)
        err(EXIT_FAILURE, "open(/dev/zero) failed");*/

    count = 0;
    for (i = 0;; i++) {
        if (tests[i][1] == NULL)
            break;

        printf("message %d\n", ++count);

        if (isdigit(*tests[i][0]))
            if (strchr(tests[i][0], ':') != NULL) {
                in6.sin6_family = AF_INET6;
                if (inet_pton(AF_INET6, tests[i][0], &in6.sin6_addr) != 1)
                    errx(EXIT_FAILURE, "inet_pton() failed");
                status = hcfi_connect(NULL, NULL, (void*)&in6);
            } else {
                in.sin_family = AF_INET;
                if (inet_aton(tests[i][0], &in.sin_addr) != 1)
                    errx(EXIT_FAILURE, "inet_aton() failed");
                status = hcfi_connect(NULL, NULL, (void*)&in);
            }
        else
            status = hcfi_connect(NULL, NULL, NULL);

        symval_i = "[ID]";
        symval_j = "forest.example";
        symval_auth_type = *tests[i][0] == 'a' ? "PLAIN" : "";

        if (status == SMFIS_CONTINUE)
            status = hcfi_envfrom(NULL, &tests[i++][1]);

        for (; tests[i][0] == NULL; i++)
            if (status == SMFIS_CONTINUE)
                status = hcfi_envrcpt(NULL, &tests[i][1]);

        for (; tests[i][0] != NULL; i++)
            if (status == SMFIS_CONTINUE)
                status = hcfi_header(NULL, tests[i][0], tests[i][1]);

        if (status == SMFIS_CONTINUE)
            status = hcfi_eom(NULL);

        if (status != SMFIS_ACCEPT)
            errx(EXIT_FAILURE, "test message not accepted");

        hcfi_close(NULL);
    }

    for (; cover_ipaddrs; cover_ipaddrs = next_addr) {
        next_addr = cover_ipaddrs->next;
        free(cover_ipaddrs);
    }
    free_strings(cover_domains);
    return MI_SUCCESS;
}
