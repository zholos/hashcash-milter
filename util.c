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

#include "sha1.h"
#include "util.h"

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>


const char alphabet[65+1] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";


/* This will use malloc() and will fail if that fails or if size overflows */
struct string* string_copy(const char* s) {
    size_t len, size;
    struct string* str;

    len = strlen(s);
    size = sizeof *str + len + 1;
    if (size < len || (str = malloc(size)) == NULL)
        return NULL;

    memset(str, 0, sizeof *str);
    strcpy(str->string, s);
    return str;
}

void free_strings(struct string* s) {
    struct string* t;
    while (s != NULL) {
        t = s;
        s = s->next;
        free(t);
    }
}

void free_integers(struct integer* s) {
    struct integer* t;
    while (s != NULL) {
        t = s;
        s = s->next;
        free(t);
    }
}


struct ipaddr* parse_ipaddrs(char* list) {
    char *item, *sep, *end;
    int len;
    long net;
    struct ipaddr *addr, *addrs = NULL;

    do {
        if ((list = strpbrk(item = list, ",; ")) != NULL)
            *list++ = '\0';
        if (!*item)
            continue;

        if ((addr = calloc(1, sizeof *addr)) == NULL)
            err(EXIT_FAILURE, "calloc() failed");

        if ((sep = strchr(item, '/')) != NULL)
            *sep = '\0';

        /* parse address part */
        if (inet_pton(AF_INET6, item, &addr->addr.in6) == 1) {
            addr->family = AF_INET6;
            len = 128;
        } else if (inet_aton(item, &addr->addr.in) == 1) {
            addr->family = AF_INET;
            len = 32;
        } else {
            if (sep != NULL)
                *sep = '/';
            errx(EXIT_FAILURE, "can't parse address in '%s'", item);
        }

        /* parse optional netmask part */
        if (sep != NULL) {
            net = strtol(sep + 1, &end, 10);
            if (!isdigit(sep[1]) || *end || net < 0 || net > len) {
                *sep = '/';
                errx(EXIT_FAILURE, "can't parse netmask in '%s'", item);
            }
            addr->net = net;
        } else
            addr->net = len;

        addr->next = addrs;
        addrs = addr;
    } while (list != NULL);

    return addrs;
}

int match_ipaddr_in(const struct in_addr* in, const struct ipaddr* match) {
    for (; match != NULL; match = match->next)
        if (match->family == AF_INET)
            if (match->net == 0 ||
                    ntohl(match->addr.in.s_addr) >> 32 - match->net ==
                               ntohl(in->s_addr) >> 32 - match->net)
                return 1;
    return 0;
}

int match_ipaddr_in6(const struct in6_addr* in6, const struct ipaddr* match) {
    int i, bits, bytes;

    for (; match != NULL; match = match->next)
        if (match->family == AF_INET6) {
            bytes = match->net / 8;
            bits = match->net % 8;
            for (i = 0; i < bytes; i++)
                if (match->addr.in6.s6_addr[i] != in6->s6_addr[i])
                    goto different;
            if (bits == 0 ||
                    match->addr.in6.s6_addr[i] >> 8 - bits ==
                               in6->s6_addr[i] >> 8 - bits)
                return 1;
        different:
            ;
        }

    return 0;
}

int match_ipaddr(void* hostaddr, const struct ipaddr* match) {
    int i;
    struct in_addr local;
    const struct sockaddr_in *in;
    const struct sockaddr_in6 *in6;

    switch (((struct sockaddr*)hostaddr)->sa_family) {
    case AF_INET:
        in = hostaddr;
        return match_ipaddr_in(&in->sin_addr, match);
    case AF_INET6:
        in6 = hostaddr;
        for (i = 0; i < 10; i++)
            if (in6->sin6_addr.s6_addr[i] != (i < 10 ? 0 : 0xff))
                goto not_v4mapped;
        /* try an IPv4-mapped address as an IPv4 address too */
        memcpy(&local.s_addr, &in6->sin6_addr.s6_addr[12], 4);
        if (match_ipaddr_in(&local, match))
            return 1;
    not_v4mapped:
        return match_ipaddr_in6(&in6->sin6_addr, match);
    case AF_LOCAL:
        /* for local domain sockets behave as if connected
           from 127.0.0.1 or ::1 */
        local.s_addr = htonl(INADDR_LOOPBACK);
        return match_ipaddr_in(&local, match) ||
               match_ipaddr_in6(&in6addr_loopback, match);
    }

    return 0;
}


struct string* parse_domains(char* list) {
    char* item;
    struct string *dom, *doms = NULL;

    do {
        if ((list = strpbrk(item = list, ",; ")) != NULL)
            *list++ = '\0';
        if (!*item)
            continue;

        if ((dom = string_copy(item)) == NULL)
            errx(EXIT_FAILURE, "memory allocation failed");

        dom->next = doms;
        doms = dom;
    } while (list != NULL);

    return doms;
}

int match_domain(const char* dom, const struct string* match) {
    for (; match != NULL; match = match->next)
        if (!strcasecmp(match->string, dom))
            return 1;

    return 0;
}


int match_address(const char* addr, const struct string* match) {
    const char* domain = strchr(addr, '\0') + 1;

    for (; match != NULL; match = match->next)
        if (!strcmp(addr, match->string) &&
                !strcasecmp(domain, strchr(match->string, '\0') + 1))
            return 1;

    return 0;
}

struct string* find_token(const char* addr, struct string* tokens) {
    size_t local_len, domain_len;
    const char *domain, *res, *at, *end;

    local_len = strlen(addr);
    domain = addr + local_len + 1;
    domain_len = strlen(domain);

    for (; tokens != NULL; tokens = tokens->next) {
        res = strchr(strchr(strchr(tokens->string, ':') + 1, ':') + 1, ':') + 1;
        at = strchr(res, '@');

        /* the comparison is the same as in match_address */
        /* a different comparison would mean that a stamp can match multiple
           recipients in a single message, precluding an in-place token_truncate
           and falsely triggering the double-spend test */
        if ((size_t)(at - res) == local_len && !strncmp(addr, res, local_len)) {
            end = strchr(at++, ':');
            if ((size_t)(end - at) == domain_len &&
                    !strncasecmp(domain, at, domain_len))
                return tokens;
        }
    }

    return NULL;
}


/* Parses a token (removing whitespace and checking syntax), but doesn't
   validate it. Guarantees that there are precisely 6 colons in the token,
   that the version is 1, that the bits value is within the range 0-160, that
   the date field contains only, and at least six, digits, and that the resource
   contains exactly one '@' character.
   dest must be at least strlen(token)+1 characters */
int parse_token(const char* value, char* token) {
    const char* s;
    char* d;
    long bits;
    int len;

    if (token != NULL) {
        d = token;
        for (s = value; *s; s++)
            if (!isspace(*s))
                *d++ = *s;
        *d = '\0';
        s = token;
    } else
        s = value;

    /* version */
    if (*s++ != '1' || *s++ != ':')
        return -1;

    /* bits */
    if (!isdigit(*s) ||
            (bits = strtol(s, (char**)&s, 10)) < 0 || bits > 160 || *s != ':')
        return -1;
    s++;

    /* date */
    len = 0;
    for (; isdigit(*s); s++)
        if (len < 6)
            len++;
    if (len < 6)
        return -1;
    if (*s++ != ':')
        return -1;

    /* resource */
    s += strcspn(s, "@:");
    if (*s++ != '@')
        return -1;
    s += strcspn(s, "@:");
    if (*s++ != ':')
        return -1;

    /* ext */
    if ((s = strchr(s, ':')) == NULL)
        return -1;
    s++;

    /* rand */
    s += strspn(s, alphabet);
    if (*s++ != ':')
        return -1;

    /* counter */
    s += strspn(s, alphabet);
    if (*s)
        return -1;

    return 0;
}

/* returns valid bits, or -1=futuristic, -2=expired, -5=invalid */
int token_value(const char* token, const char* date1, const char* date2) {
    struct sha1_info hash;
    int i, bits, cmp1, cmp2;
    const char* field;
    size_t len;

    /* find bits */
    field = strchr(token, ':') + 1;
    bits = strtol(field, NULL, 10);

    /* check date */
    field = strchr(field, ':') + 1;
    len = strchr(field, ':') - field;
    if (len > 12)
        len = 12;

    cmp1 = strncmp(field, date1, len);
    cmp2 = strncmp(field, date2, len);
    if (strcmp(date1, date2) <= 0) {
        if (cmp1 < 0)
            return -2;
        if (cmp2 > 0)
            return -1;
    } else /* turn of the century */
        if (cmp1 < 0 && cmp2 > 0)
            return -2;

    /* check preimage bits */
    sha1_begin(&hash);
    sha1_string(&hash, token, strlen(token));
    sha1_done(&hash);

    for (i = 0; i < bits; i += 32)
        if (hash.digest[i / 32] >> (32 > bits - i ? 32 - (bits - i) : 0))
            return -5;

    return bits;
}

void memrev(char* s, size_t len) {
    char* e;
    char c;

    for (e = s + len; s < e;) {
        c = *s;
        *s++ = *--e;
        *e = c;
    }
}

void memror(char* s, size_t len, size_t shift) {
    memrev(s, len - shift);
    memrev(s + (len - shift), shift);
    memrev(s, len);
}

/* Truncate token for recording in double-spend database. The cost of minting
   is mostly independent of the length of the stamp, so without truncation it
   would be possible to pollute the database with very long but valid stamps. */
/* The date is also moved to the first field so that expired stamps will be
   lexicographically first. */
void token_truncate(char* token) {
    char *sep[6], *d;
    const char *end, *s;
    size_t res_len, len, reduced;
    int i;

    sep[0] = strchr(token, ':');
    for (i = 1; i < 6; i++)
        sep[i] = strchr(sep[i-1] + 1, ':');
    end = strchr(sep[5], '\0');

    memror(token, sep[2] - token + 1, sep[2] - sep[1]);
    sep[0] = strchr(token, ':');
    sep[1] = strchr(sep[0] + 1, ':');

    /* A reasonable token size, rounded up to a SHA-1 block */
    res_len = sep[3] - sep[2] - 1;
    reduced = (19 + res_len + 387 + 9 + 63) / 64 * 64 - 9;
    if (reduced < res_len)
        reduced = res_len;
    len = end - token;

    if (len <= reduced)
        return;

    /* Remove counter (from the front), ... */
    for (d = sep[5] + 1; *d && len > reduced; len--)
        *d++ = '\0';
    /* ... then ext (whole), ... */
    if (len > reduced)
        for (d = sep[3] + 1; *d != ':'; len--)
            *d++ = '\0';
    /* ... then rand (from the back), ... */
    for (d = sep[5] - 1; *d != ':' && len > reduced; len--)
        *d-- = '\0';
    /* ... then bits (whole), ... */
    if (len > reduced)
        for (d = sep[1] + 1; *d != ':'; len--)
            *d++ = '\0';
    /* ... then part of date (from the back) */
    d = sep[0];
    for (; d - token > 12 && len > reduced; len--)
        *--d = '\0';

    for (s = token, d = token; s != end; s++)
        if (*s)
            *d++ = *s;
    *d = '\0';
}

/* Checks whether the header is not a token but a specific special value. */
int token_special(const char* value, const char* special) {
    size_t special_len = strlen(special);

    for (; isspace(*value); value++);
    if (!strncmp(value, special, special_len)) {
        value += special_len;
        for (; isspace(*value); value++);
        return !*value;
    } else
        return 0;
}


/* This uses gmtime_r and will only fail if that fails.
   date should have date_len+1 characters,
   date_len should be 12 for a full date */
int format_date(time_t base, long delta, char* date, size_t date_len) {
    time_t tt;
    struct tm tm;

    if (delta >= 0) {
        tt = base + delta;
        if (tt < base)
            tt = base;
    } else
        tt = base - (-delta);
        if (tt > base)
            tt = base;

    if (gmtime_r(&tt, &tm) == NULL)
        return -1;

    snprintf(date, date_len + 1, "%02d%02d%02d%02d%02d%02d",
            tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);

    return 0;
}


/* Returns {-1, 0, 1} if now {<, =, >} start,
   and only calculates delta if now >= start */
int ts_delta(struct timespec* now, const struct timespec* start) {
    if (now->tv_sec > start->tv_sec ||
            now->tv_sec == start->tv_sec && now->tv_nsec >= start->tv_nsec) {
        if (now->tv_nsec >= start->tv_nsec) {
            now->tv_sec -= start->tv_sec;
            now->tv_nsec -= start->tv_nsec;
        } else {
            now->tv_sec -= start->tv_sec + 1;
            now->tv_nsec += 1000000000 - start->tv_nsec;
        }
        return now->tv_sec != 0 || now->tv_nsec != 0;
    } else
        return -1;
}


/* x / y * 10^n */
long divexp10(uint64_t x, uint64_t y, int n) {
    for (; n > 0 && x < UINT64_MAX / 10; n--)
        x *= 10;
    for (; n > 0; n--)
        y /= 10;
    return y != 0 ? x / y : 0;
}


/* user and group may not be NULL */
void chuid(const char* user, const char* group, const char* rootdir) {
    struct passwd* pw = NULL;
    struct group* gr = NULL;
    uid_t uid = -1, ruid, euid, suid;
    gid_t gid = -1, rgid, egid, sgid;

    /* find IDs from names */
    errno = 0;
    if (user != NULL && (pw = getpwnam(user)) == NULL)
        if (errno)
            err(EXIT_FAILURE, "getpwnam(%s) failed", user);
        else
            errx(EXIT_FAILURE, "user '%s' not found", user);

    if (group != NULL && (gr = getgrnam(group)) == NULL)
        if (errno)
            err(EXIT_FAILURE, "getgrnam(%s) failed", group);
        else
            errx(EXIT_FAILURE, "group '%s' not found", group);

    /* change root directory */
    if (rootdir != NULL) {
        if (chroot(rootdir) == -1)
            errx(EXIT_FAILURE, "chroot(%s) failed", rootdir);
        if (chdir("/") == -1)
            errx(EXIT_FAILURE, "chdir(/) failed after chroot(%s)", rootdir);
    }

    /* change IDs */
    if (pw != NULL && getuid() != pw->pw_uid &&
            initgroups(user, pw->pw_gid) == -1)
        if (errno == EPERM)
            goto no_perm;
        else
            err(EXIT_FAILURE, "initgroups() failed");
    if (pw != NULL || gr != NULL) {
        gid = gr != NULL ? gr->gr_gid : pw->pw_gid;
        if (setresgid(gid, gid, gid) == -1)
            if (errno == EPERM)
                goto no_perm;
            else
                err(EXIT_FAILURE, "setresgid() failed");
    }
    if (pw != NULL) {
        uid = pw->pw_uid;
        if (setresuid(uid, uid, uid) == -1)
            if (errno == EPERM)
                goto no_perm;
            else
                err(EXIT_FAILURE, "setresuid() failed");
    }

    /* check changes */
    if (getresgid(&rgid, &egid, &sgid) == -1)
        err(EXIT_FAILURE, "getresgid() failed");
    if (gr != NULL && (rgid != gid || egid != gid || sgid != gid))
        errx(EXIT_FAILURE, "group ID not changed correctly");
    if (getresuid(&ruid, &euid, &suid) == -1)
        err(EXIT_FAILURE, "getresuid() failed");
    if (pw != NULL && (ruid != uid || euid != uid || suid != uid))
        errx(EXIT_FAILURE, "user ID not changed correctly");

    /* check whether we can become root again */
    if (pw != NULL && (setresuid(-1, 0, -1) != -1 || errno != EPERM))
        errx(EXIT_FAILURE,
             "managed to become root again after dropping privileges");
    return;

no_perm:
    if (gr != NULL)
        if (pw != NULL)
            errx(EXIT_FAILURE,
                "not permitted to change user to '%s' and group to '%s'",
                 pw->pw_name, gr->gr_name);
        else
            errx(EXIT_FAILURE,
                 "not permitted to change group to '%s'", gr->gr_name);
    else
        errx(EXIT_FAILURE, "not permitted to change user to '%s'", pw->pw_name);
}

void close_stdio(int null_fd) {
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
}


/* This will use write() and only fail if that fails */
int write_long(int fd, long value) {
    char buf[64];
    size_t len;
    ssize_t status;

    snprintf(buf, sizeof buf, "%ld", value);
    for (len = strlen(buf); len != 0;) {
        if ((status = write(fd, buf, len)) == -1) {
            if (errno != EINTR)
                return -1;
        } else
            len -= status;
    }
    return 0;
}


char* strdup_checked(const char* s) {
    char* d;
    if ((d = strdup(s)) == NULL)
        err(EXIT_FAILURE, "strdup() failed");
    return d;
}

void rootdir_path(char* path, const char* rootdir) {
    size_t len;

    len = strlen(rootdir);
    if (len > 0 && rootdir[len-1] == '/')
        len--;
    if (!strncmp(path, rootdir, len))
        if (path[len] == '/')
            memmove(path, path + len, strlen(path) - len + 1);
        else if (path[len] == '\0' && len > 0)
            strcpy(path, "/");
}
