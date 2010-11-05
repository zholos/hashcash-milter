/*
 * Part of Hashcash Milter version 0.1.2 from <http://althenia.net/hashcash>.
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

#include "rfc2822.h"
#include "sha1.h"
#include "util.h"

#include <libmilter/mfapi.h>

#ifdef USE_DB185
#include <db_185.h>
#else
#include <db.h>
#endif

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#define COUNTER_MAX 16
/* 65^1 + 65^2 + ... + 65^16 = 10^29 hashes */
/* 10^29 hashes / 1 Ghash/sec = 3*10^12 years */

#define RANDOM_LEN 16
/* 1000 messages/second = 10^8 messages/day */
/* 65^16 = 10^29 choices: collision probability/day = 5*10^-14 */


/* configuration */
int cover_auth = 0;
struct ipaddr* cover_ipaddrs = NULL;
struct string* cover_domains = NULL;
int mint_bits = 0, reduce_bits = 0;
int check_bits = 0;
long timeout = 0;

int random_fd;
DB* db_spent = NULL;
pthread_mutex_t db_mutex;
time_t db_sync = 0;

struct hcfi_priv {
    /* decision parameters */
    int ipaddr; /* 1=outgoing, 2=incoming, 0=unknown */
    int mode;   /* 1=mint,     2=check,    0=passive */
    int ignore; /* perform only passive actions */
    /*
        active actions:
            mint and add tokens (mint mode only)
            check tokens (check mode only)
        passive actions:
            remove skip instruction (not check mode)
            remove invalid auth results (not mint mode)
    */

    /* MTA parameters */
    char* queue_id;
    char* my_hostname;

    /* message information */
    struct string* env_rcpts;
    struct string* msg_rcpts;
    struct string* tokens; /* only syntactically valid tokens */
    int neutral; /* syntactically-invalid tokens seen */

    /* positions of headers */
    int header_count;
    int hashcash_pos; /* where X-Hashcash headers are inserted */
    int hashcash_count[2]; /* encountered (X-)Hashcash headers */
    int auth_results_pos; /* where Authentication-Results are inserted */
    int auth_results_count; /* encountered Authentication-Results */

    /* delayed actions */
    int remove_hashcash; /* remove skip instruction */
    struct integer* remove_auth_results; /* invalid to remove */
    int warned_auth_results; /* warned if hostname not available */

};

char* null_queue_id = "(unknown)";

char header_hashcash[] = "X-Hashcash"; /* +2 is used as "Hashcash" */
char header_auth_results[] = "Authentication-Results";


sfsistat hcfi_connect(SMFICTX* ctx, char* hostname, _SOCK_ADDR* hostaddr) {
    struct hcfi_priv* priv;

    /* allocate and initialize private storage */
    if ((priv = calloc(1, sizeof *priv)) == NULL) {
        syslog(LOG_ERR, "memory allocation failed");
        return SMFIS_ACCEPT;
    }

    priv->queue_id = null_queue_id;
    priv->my_hostname = NULL;
    priv->env_rcpts = NULL;
    priv->msg_rcpts = NULL;
    priv->tokens = NULL;
    priv->neutral = 0;
    priv->remove_auth_results = NULL;

    if (smfi_setpriv(ctx, priv) == MI_FAILURE) {
        syslog(LOG_ERR, "smfi_setpriv() failed");
        smfi_setpriv(ctx, NULL);
        free(priv);
        return SMFIS_ACCEPT;
    }

    /* check if we need to cover this message based on IP address */
    if (cover_ipaddrs != NULL)
        if (hostaddr == NULL) {
            syslog(LOG_WARNING, "client host address not supplied by MTA");
            priv->ipaddr = 0;
        } else
            priv->ipaddr = match_ipaddr(hostaddr, cover_ipaddrs) ? 1 : 2;
    else
        priv->ipaddr = 2;

    return SMFIS_CONTINUE;
}

void get_syms(SMFICTX* ctx) {
    const char* symval;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    if (priv->queue_id == null_queue_id) {
        symval = smfi_getsymval(ctx, "i");
        if (symval != NULL && *symval &&
                (priv->queue_id = strdup(symval)) == NULL) {
            syslog(LOG_WARNING,
                   "memory allocation failed, queue ID will not be logged");
            priv->queue_id = null_queue_id;
        }
    }

    if (priv->my_hostname == NULL) {
        symval = smfi_getsymval(ctx, "j");
        if (symval != NULL && *symval &&
                (priv->my_hostname = strdup(symval)) == NULL)
            syslog(LOG_ERR, "memory allocation failed, "
                   "local hostname will not be available");
    }
}

sfsistat hcfi_envfrom(SMFICTX* ctx, char** argv) {
    char* mailbox;
    const char* auth_type;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    /* store queue ID and local hostname */
    if (priv->queue_id != null_queue_id) {
        free(priv->queue_id);
        priv->queue_id = null_queue_id;
    }
    get_syms(ctx);

    /* initialize per-message variables */
    free_strings(priv->env_rcpts); priv->env_rcpts = NULL;
    free_strings(priv->msg_rcpts); priv->msg_rcpts = NULL;
    free_strings(priv->tokens);    priv->tokens = NULL;

    priv->header_count = 0;
    priv->hashcash_pos = 0;
    priv->hashcash_count[0] = 0;
    priv->hashcash_count[1] = 0;
    priv->auth_results_pos = 0;
    priv->auth_results_count = 0;

    priv->remove_hashcash = -1;
    free_integers(priv->remove_auth_results); priv->remove_auth_results = NULL;
    priv->warned_auth_results = 0;

    /* decide if message is outgoing or incoming */
    if (cover_auth &&
            (auth_type = smfi_getsymval(ctx, "{auth_type}")) != NULL &&
            *auth_type)
        priv->mode = 1;
    else
        priv->mode = priv->ipaddr;

    if (!priv->mode)
        syslog(LOG_NOTICE,
               "%s: can't decide whether message is outgoing or incoming",
               priv->queue_id);

    /* check if we're configured not to do anything for this direction */
    if (priv->mode)
        priv->ignore = (priv->mode == 1 ? mint_bits : check_bits) == 0;
    else
        priv->ignore = 1;

    /* check if we need to cover this message based on sender domain */
    if (priv->mode == 1 && !priv->ignore && cover_domains != NULL) {
        if ((mailbox = malloc(strlen(argv[0]) + 1)) == NULL) {
            syslog(LOG_ERR, "memory allocation failed");
            goto failed;
        }
        if (rfc5321_mailbox(argv[0], mailbox) == -1) {
            syslog(LOG_NOTICE, "%s: couldn't parse sender", priv->queue_id);
            free(mailbox);
            goto failed;
        }
        if (!match_domain(strchr(mailbox, '\0') + 1, cover_domains))
            priv->ignore = 1;
        free(mailbox);
    }

    return SMFIS_CONTINUE;

failed:
    /* keep running to perform passive actions */
    priv->ignore = 1;
    return SMFIS_CONTINUE;
}

sfsistat hcfi_envrcpt(SMFICTX *ctx, char** argv) {
    size_t len, size;
    struct string* mailbox;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    /* store queue ID and local hostname;
       Postfix chooses a queue ID after it accepts the first recipient,
       which should be around here */
    get_syms(ctx);

    if (priv->ignore)
        return SMFIS_CONTINUE;

    /* list envelope recipients */
    len = strlen(argv[0]);
    size = sizeof *mailbox + len + 1;
    if (size < len || (mailbox = calloc(1, size)) == NULL) {
        syslog(LOG_ERR, "memory allocation failed");
        goto failed;
    }
    if (rfc5321_mailbox(argv[0], mailbox->string) == -1) {
        syslog(LOG_NOTICE, "%s: couldn't parse recipient", priv->queue_id);
        free(mailbox);
        goto failed;
    }

    /* only list unique recipients */
    if (!match_address(mailbox->string, priv->env_rcpts)) {
        mailbox->next = priv->env_rcpts;
        priv->env_rcpts = mailbox;
    } else
        free(mailbox);

    return SMFIS_CONTINUE;

failed:
    /* keep running to perform passive actions */
    priv->ignore = 1;
    return SMFIS_CONTINUE;
}

sfsistat hcfi_header(SMFICTX* ctx, char* name, char* value) {
    char *list, *item, *next;
    int status, x_hashcash;
    size_t len, size;
    struct string *mailbox, *token;
    struct integer* remove;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    priv->header_count++;

    /* list message recipients */
    if (!priv->ignore && (!strcasecmp(name, "To") || !strcasecmp(name, "CC"))) {
        len = strlen(value);
        size = len + 2;
        if (size < len || (list = malloc(size)) == NULL) {
            syslog(LOG_ERR, "memory allocation failed");
            goto failed;
        }
        if (rfc2822_address_list(value, list) == -1) {
            syslog(LOG_NOTICE,
                   "%s: couldn't parse address headers", priv->queue_id);
            free(list);
            goto failed;
        }
        for (item = list; *item; item = next) {
            next = strchr(item, '\0') + 1;
            if (!*next) {
                syslog(LOG_ERR, "%s: internal error: address parser failed",
                       priv->queue_id);
                free(list);
                goto failed;
            }
            next = strchr(next, '\0') + 1;

            /* only list unique recipients */
            if (!match_address(item, priv->msg_rcpts)) {
                len = next - item; /* includes null */
                size = sizeof *mailbox + len;
                if (size < len || (mailbox = malloc(size)) == NULL) {
                    syslog(LOG_ERR, "memory allocation failed");
                    free(list);
                    goto failed;
                }

                memcpy(mailbox->string, item, len);
                mailbox->next = priv->msg_rcpts;
                priv->msg_rcpts = mailbox;
            }
        }
        free(list);
        return SMFIS_CONTINUE;
    }

    if ((x_hashcash = !strcasecmp(name, header_hashcash)) ||
                      !strcasecmp(name, header_hashcash + 2)) {
        if (priv->mode == 2) {
            if (!priv->ignore) {
                /* parse hashcash tokens for incoming messages */
                len = strlen(value);
                size = sizeof *token + len + 1;
                if (size < len || (token = calloc(1, size)) == NULL) {
                    syslog(LOG_ERR, "memory allocation failed");
                    goto failed;
                }

                if (parse_token(value, token->string) != -1) {
                    token->next = priv->tokens;
                    priv->tokens = token;
                } else {
                    /* ignore malformed tokens */
                    priv->neutral = 1;
                    free(token);
                }
            }
        } else {
            /* skip messages covered by tokens for outgoing messages */
            priv->ignore = 1;
            if (priv->remove_hashcash < 0) {
                priv->hashcash_count[x_hashcash]++;
                if (token_special(value, "skip"))
                    priv->remove_hashcash = x_hashcash;
            }
        }
        return SMFIS_CONTINUE;
    }

    /* try to insert headers after trace headers */
    if ((!strcasecmp(name, "Return-Path") || !strcasecmp(name, "Received"))) {
        priv->auth_results_pos = priv->hashcash_pos = priv->header_count;
        return SMFIS_CONTINUE;
    }

    if (priv->mode != 1 && !strcasecmp(name, header_auth_results)) {
        /* try to insert auth results after other auth results */
        /* inserting them in a different position would require a different
           strategy for removing incorrect auth results headers */
        priv->auth_results_pos = priv->header_count;
        priv->auth_results_count++;

        /* remove auth results headers that only we should be adding */
        if (priv->my_hostname == NULL) {
            if (!priv->warned_auth_results) {
                /* we might check some later headers if the hostname becomes
                   available */
                syslog(LOG_NOTICE, "%s: local hostname not supplied by MTA, "
                       "Authentication-Results header not checked",
                       priv->queue_id);
                priv->warned_auth_results = 1;
            }
            return SMFIS_CONTINUE;
        }

        len = strlen(value);
        size = len + 4;
        if (size < len || (list = malloc(size)) == NULL) {
            syslog(LOG_ERR, "memory allocation failed");
            goto failed;
        }
        status = rfc5451_methods(value, list);
        if (status != 0)
            syslog(LOG_NOTICE,
                   "%s: couldn't parse Authentication-Results header",
                   priv->queue_id);

        if (status != -1 && !strcasecmp(list, priv->my_hostname)) {
            item = strchr(list, '\0') + 1;
            if (item[0] == '1' && !item[1]) {
                item += 2;
                for (; *item; item = strchr(item, '\0') + 1) {
                    if (!strcmp(item, "x-hashcash")) {
                        if ((remove = calloc(1, sizeof *remove)) == NULL) {
                            syslog(LOG_ERR, "memory allocation failed");
                            free(list);
                            goto failed;
                        }
                        remove->integer = priv->auth_results_count;
                        remove->next = priv->remove_auth_results;
                        priv->remove_auth_results = remove;
                        break;
                    }
                }
            }
        }
        free(list);
        return SMFIS_CONTINUE;
    }

    return SMFIS_CONTINUE;

failed:
    /* keep running to perform passive actions */
    priv->ignore = 1;
    return SMFIS_CONTINUE;
}


struct iteration {
    char* counter_last;
    int bits;
    int error;
    long tick_tries;
    long tries_per_tick;
    uint64_t total_tries;
    struct timespec ts_start, ts;
    SMFICTX* ctx;
    const char* queue_id;
};

#undef CLOCK
#ifdef CLOCK_THREAD_CPUTIME_ID
    #define CLOCK CLOCK_THREAD_CPUTIME_ID
#else
    #define CLOCK CLOCK_MONOTONIC
#endif

int tick(struct iteration* it) {
    struct timespec last_time, tick_delta;

    it->total_tries += it->tick_tries;
    it->tick_tries = 0;

    if (timeout) {
        last_time = it->ts;

        if (clock_gettime(CLOCK, &it->ts) == -1) {
            syslog(LOG_ERR, "%s: clock_gettime() failed: %m", it->queue_id);
            it->error = 1;
            return 1;
        }

        if (ts_delta(&it->ts, &it->ts_start) >= 0) {
            if (it->ts.tv_sec >= timeout) {
                syslog(LOG_INFO, "%s: spent too long minting", it->queue_id);
                it->error = 1;
                return 1;
            }

            /* report progress every second if timeout is set */
            if (it->ts.tv_sec > last_time.tv_sec)
                smfi_progress(it->ctx);

            /* scale tries_per_tick to one tick per 200-300 ms */
            tick_delta = it->ts;
            if (ts_delta(&tick_delta, &last_time) >= 0) {
                if (tick_delta.tv_sec > 0 || tick_delta.tv_nsec > 500000000l)
                    it->tries_per_tick /= 2;
                else if (tick_delta.tv_nsec > 300000000l)
                    it->tries_per_tick = it->tries_per_tick * 5 / 6;
                else if (tick_delta.tv_nsec < 200000000l)
                    if (it->tries_per_tick < LONG_MAX / 2)
                        it->tries_per_tick *= 2;

                if (it->tries_per_tick < 1)
                    it->tries_per_tick = 1;
            }
        }
    }

    return 0;
}

int iterate_counter(struct iteration* it,
                    const struct sha1_info* hash_head, int len) {
    struct sha1_info hash;
    int c, i;

    for (c = 0; c < (int)(sizeof alphabet - 1); c++) {
        hash = *hash_head;
        sha1_char(&hash, alphabet[c]);

        if (len > 0) {
            if (iterate_counter(it, &hash, len - 1)) {
                it->counter_last[-len] = alphabet[c];
                return 1;
            }
        } else {
            sha1_done(&hash);

            for (i = 0; i < it->bits / 32; i++)
                if (hash.digest[i])
                    goto again;
            if (it->bits % 32 != 0 && hash.digest[i] >> 32 - it->bits % 32)
                goto again;

            *it->counter_last = alphabet[c];
            return 1; /* found one */

        again:
            if (++it->tick_tries == it->tries_per_tick && tick(it))
                return 1;
        }
    }

    return 0;
}

void hcfi_eom_mint(SMFICTX* ctx) {
    struct iteration it;
    time_t tt;
    ssize_t random_left = 0;
    unsigned char random[RANDOM_LEN*2];
    char date[6+1];
    const char *local, *domain;
    size_t size, print_size, local_len, domain_len;
    struct string *addr, *token, *tokens;
    char* s;
    int len;
    struct sha1_info hash;
    char counter[COUNTER_MAX];
    long ktries_per_sec;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    /* timeout */
    if (clock_gettime(CLOCK, &it.ts_start) == -1) {
        syslog(LOG_ERR, "%s: clock_gettime() failed: %m", priv->queue_id);
        return;
    }
    it.bits = mint_bits;
    it.error = 0;
    it.tick_tries = 0;
    it.tries_per_tick = 100;
    it.total_tries = 0;
    it.ts.tv_sec = 0;
    it.ts.tv_nsec = 0;
    it.ctx = ctx;
    it.queue_id = priv->queue_id;

    /* current date */
    if ((tt = time(NULL)) == (time_t)-1) {
        syslog(LOG_ERR, "%s: time() failed", priv->queue_id);
        return;
    }
    if (format_date(tt, 0, date, sizeof date - 1) == -1) {
        syslog(LOG_ERR, "%s: gmtime_r() failed", priv->queue_id);
        return;
    }

    /* reduce mint bits */
    if (reduce_bits != 0 && reduce_bits < mint_bits) {
        size = 0;
        for (addr = priv->msg_rcpts; addr != NULL; addr = addr->next)
            size++;

        for (; it.bits > reduce_bits && size > 1; size /= 2)
            it.bits--;
    }

    /* repeat for each recipient */
    tokens = NULL;
    token = NULL;
    for (addr = priv->msg_rcpts; addr != NULL; addr = addr->next) {
        local = addr->string;
        local_len = strlen(local);
        domain = local + local_len + 1;
        domain_len = strlen(domain);

        if (!rfc2822_is_dot_atom_text(local) ||
            !rfc2822_is_dot_atom_text(domain)) {
            syslog(LOG_NOTICE, "%s: skipped stamp because recipient address "
                   "requires quoting", priv->queue_id);
            continue;
        }

        /* prepare a token */
        print_size = 1 + 1                          /* version : */
                   + 3 + 1                          /* bits up to 160 : */
                   + 6 + 1                          /* date : */
                   + local_len + 1 + domain_len + 1 /* resource : */
                   + 0 + 1;                         /* extension : */
        size = sizeof *token
             + print_size
             + RANDOM_LEN + 1 /* random : */
             + COUNTER_MAX    /* counter */
             + 1;             /* null */
        if (size < local_len || local_len - size < domain_len ||
                (token = malloc(size)) == NULL) {
            syslog(LOG_ERR, "memory allocation failed");
            goto failed;
        }

        /* first part of token */
        token->string[print_size] = '\0';
        if (snprintf(token->string, print_size+2, "1:%d:%s:%s@%s::", it.bits,
                     date, local, domain) < 0 || token->string[print_size]) {
            syslog(LOG_ERR, "%s: internal error: snprintf() failed",
                   priv->queue_id);
            goto failed;
        }
        s = strchr(token->string, '\0');

        /* write rand into token */
        for (len = 0; len < RANDOM_LEN;) {
            if (random_left == 0) {
                do
                    random_left = read(random_fd, random, sizeof random);
                while (random_left == -1 && errno == EINTR);
                if (random_left == -1) {
                    syslog(LOG_ERR,
                           "%s: read(/dev/urandom) failed: %m", priv->queue_id);
                    goto failed;
                } else if (random_left == 0)  {
                    syslog(LOG_ERR,
                           "%s: read(/dev/urandom) failed: end of file",
                           priv->queue_id);
                    goto failed;
                }
            }

            /* draw uniformly-distributed random letter by rejection sampling */
            random_left--;
            if (random[random_left] <
                    UCHAR_MAX - (UCHAR_MAX % sizeof alphabet - 1)) {
                *s++ = alphabet[random[random_left] % (sizeof alphabet - 1)];
                len++;
            }
        }
        *s++ = ':';

        /* hash initial part of string */
        sha1_begin(&hash);
        sha1_string(&hash, token->string, s - token->string);

        /* iterate counter;
           always add at least 1 character (assumed by iterate_counter()) */
        for (len = 1; len <= COUNTER_MAX; len++) {
            it.counter_last = &counter[len-1];
            if (iterate_counter(&it, &hash, len - 1))
                if (it.error)
                    goto failed;
                else
                    goto found;
        }
        syslog(LOG_ERR, "%s: internal error: COUNTER_MAX(%d) exceeded",
               priv->queue_id, COUNTER_MAX);
        goto failed;

        /* found one */
    found:
        memcpy(s, counter, len);
        s[len] = '\0';

        /* double-check token */
        if (parse_token(token->string, NULL) == -1 ||
                token_value(token->string, date, date) < it.bits) {
            syslog(LOG_ERR, "%s: internal error: minted incorrect stamp %s",
                   priv->queue_id, token->string);
            goto failed;
        }

        token->next = tokens;
        tokens = token;
        token = NULL;
    }

    if (clock_gettime(CLOCK, &it.ts) == -1) {
        syslog(LOG_ERR, "%s: clock_gettime() failed: %m", priv->queue_id);
        goto failed;
    }

    /* now that all tokens have been generated, affix them to the message */
    for (token = tokens; token != NULL; token = token->next) {
        size = strlen(token->string);
        if (size > 998 || (sizeof header_hashcash - 1) + 2 + size > 998)
            syslog(LOG_NOTICE,
                   "%s: skipped stamp that exceeds 998 character limit",
                   priv->queue_id);
        else {
            if (smfi_insheader(ctx, ++priv->hashcash_pos,
                               header_hashcash, token->string) == MI_FAILURE) {
                syslog(LOG_ERR, "%s: smfi_insheader() failed", priv->queue_id);
                goto failed;
            }
            syslog(LOG_INFO,
                   "%s: added stamp %s", priv->queue_id, token->string);
        }
    }

    /* log some statistics */
    if (tokens != NULL && ts_delta(&it.ts, &it.ts_start) >= 0) {
        ktries_per_sec = divexp10(it.total_tries + it.tick_tries,
            (uint64_t)it.ts.tv_sec * 1000000000l + it.ts.tv_nsec, 6);
        syslog(LOG_INFO,
            "%s: minting took %ld.%03ld seconds (%ld.%03ld Mhash/s)",
            priv->queue_id,
            (long)it.ts.tv_sec, (long)(it.ts.tv_nsec / 1000000l),
            ktries_per_sec / 1000l, ktries_per_sec % 1000l);
    }

    free_strings(tokens);
    return;

failed:
    free(token);
    free_strings(tokens);
}


void hcfi_eom_check(SMFICTX* ctx) {
    /* For each recipient the best stamp is chosen according to the ordering:
           0-160: valid stamp value
          -1: futuristic
          -2: expired
          -4: spent
          -5: invalid

       For a single recipient the result codes are:
           pass:    valid
           policy:  insufficient value, futuristic or expired
           fail:    spent or invalid
           neutral: headers seen, but none contained a stamp

       For multiple recipients the result codes are:
           pass (n bits):
               each recipient had a valid stamp for at least n bits of value
               (n >= required bits)
           partial (highest n bits):
               at least one recipient had a stamp for n bits of value
               (n >= required bits), and no recipients had spent or invalid
               (fail result) stamps
           policy (only n bits),
           policy (futuristic),
           policy (expired):
               at least one recipient had a stamp for n bits of value
               (n < required bits) / with the date in the future / with the
               date far in the past, and no recipients had spent or invalid
               (fail result) stamps
           fail (spent):
               at least one recipient had a spent stamp and no recipients had
               invalid stamps
           fail (invalid):
               at least one recipient had an invalid stamp
           neutral:
               headers seen

       When several results match the message (e.g., one stamp for 160 bits
       and one expired stamp match both "partial (highest 160 bits)" and
       "policy (expired)"), the best result is chosen according to the order
       given.
     */

    const struct string* addr;
    struct string* token;
    int value, best, min_value = 160, max_value = -5;
    time_t tt = -1;
    char date1[12+1], date2[12+1];
    char buf[998 - ((sizeof header_auth_results - 1) + 2) +
             1 + 1]; /* null, extra byte to detect overflow */
    int purged = 0;
    u_int db_flag;
    DBT db_key, db_value;
    const char* sep;
    size_t len;
    int result;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    if (priv->tokens == NULL && !priv->neutral)
        return;

    for (addr = priv->env_rcpts; addr != NULL; addr = addr->next) {
        if (!match_address(addr->string, priv->msg_rcpts))
            continue;

        best = -3; /* no stamps */

        /* iterate over tokens matching this recipient */
        for (token = find_token(addr->string, priv->tokens); token != NULL;
             token = find_token(addr->string, token->next)) {

            /* date range */
            if (tt == (time_t)-1) {
                if ((tt = time(NULL)) == (time_t)-1) {
                    syslog(LOG_ERR, "%s: time() failed", priv->queue_id);
                    return;
                }
                if (format_date(tt, -(28 + 2) * 86400,
                                date1, sizeof date1 - 1) == -1 ||
                        format_date(tt, 2 * 86400,
                                    date2, sizeof date2 - 1) == -1) {
                    syslog(LOG_ERR, "%s: gmtime_r() failed", priv->queue_id);
                    return;
                }
            }

            value = token_value(token->string, date1, date2);

            /* check double-spend database */
            if (db_spent != NULL && value >= check_bits) {
                /* mangle token for storing in database;
                   this is done in-place, but we should not access this token
                   again because all envelope recipients in the list are
                   distinct */
                token_truncate(token->string);

                memset(&db_key, 0, sizeof db_key);
                memset(&db_value, 0, sizeof db_value);

                if (pthread_mutex_lock(&db_mutex) != 0)
                    syslog(LOG_WARNING, "%s: pthread_mutex_lock() failed, "
                           "double-spend database will not be checked",
                           priv->queue_id);
                else {
                    /* purge expired stamps */
                    if (!purged) {
                        purged = 1;

                        /* don't purge around the turn of the century */
                        if (strcmp(date1, date2) > 0)
                            goto purge_done;

                        for (db_flag = R_FIRST;;) {
                            switch (db_spent->seq(db_spent, &db_key, &db_value,
                                                  db_flag)) {
                            case -1:
                                syslog(LOG_WARNING, "%s: db->seq() failed: %m; "
                                       "expired stamps will not be purged from "
                                       "double-spend database", priv->queue_id);
                            case 1:
                                goto purge_done;
                            }
                            sep = memchr(db_key.data, ':', db_key.size);
                            len = sep != NULL ?
                                      (size_t)(sep - (const char*)db_key.data) :
                                      db_key.size;
                            if (db_flag == R_FIRST) {
                                if (len > sizeof date1 - 1)
                                    len = sizeof date1 - 1;
                                if (len >= 6 &&
                                        memcmp(db_key.data, date1, len) >= 0) {
                                    db_flag = R_LAST;
                                    continue;
                                }
                            } else {
                                if (len > sizeof date2 - 1)
                                    len = sizeof date2 - 1;
                                if (len >= 6 &&
                                        memcmp(db_key.data, date2, len) <= 0)
                                    break;
                            }
                            switch (db_spent->del(db_spent, &db_key,
                                                  R_CURSOR)) {
                            case -1:
                                syslog(LOG_WARNING, "%s: db->del() failed: %m; "
                                       "expired stamps will not be purged from "
                                       "double-spend database", priv->queue_id);
                                goto purge_done;
                            case 1:
                                syslog(LOG_ERR, "%s: internal error: "
                                       "key not found in double-spend database",
                                       priv->queue_id);
                                goto purge_done;
                            }
                        }
                    purge_done:
                        memset(&db_key, 0, sizeof db_key);
                        memset(&db_value, 0, sizeof db_value);
                    }

                    /* record current stamp */
                    db_key.data = token->string;
                    db_key.size = strlen(token->string);
                    db_value.data = "";
                    db_value.size = 0;

                    switch (db_spent->put(db_spent, &db_key, &db_value,
                                          R_NOOVERWRITE)) {
                    case 1:
                        value = -4;
                        break;
                    case -1:
                        syslog(LOG_WARNING, "%s: db->put() failed: %m; "
                               "double-spend database will not be checked",
                               priv->queue_id);
                    }

                    /* sync to disk every 5 minutes */
                    if (db_sync == 0 || tt >= db_sync) {
                        if (db_sync != 0 && db_spent->sync(db_spent, 0) == -1)
                            syslog(LOG_WARNING,
                                   "%s: db->sync() failed: %m", priv->queue_id);
                        db_sync = tt + 300;
                    }

                    if (pthread_mutex_unlock(&db_mutex) != 0)
                        syslog(LOG_WARNING, "%s: pthread_mutex_unlock() failed",
                               priv->queue_id);
                }
            }

            /* out of multiple tokens for a recipient we select the best one */
            if (best < value || best == -3)
                best = value;
        }

        if (min_value > best)
            min_value = best;
        if (max_value < best)
            max_value = best;
    }

    if (priv->my_hostname == NULL) {
        syslog(LOG_WARNING, "%s: local hostname not supplied by MTA, "
            "Authentication-Results header not added", priv->queue_id);
        return;
    }

    buf[sizeof buf-2] = '\0';
    if (min_value > max_value)
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=neutral", priv->my_hostname);
    else if (min_value <= -4)
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=fail (%s)", priv->my_hostname,
            min_value == -5 ? "invalid" : "already spent");
    else if (min_value >= check_bits)
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=pass (%d bits)", priv->my_hostname, min_value);
    else if (max_value >= check_bits)
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=partial (highest %d bits)", priv->my_hostname,
            max_value);
    else if (max_value >= 0)
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=policy (only %d bits)", priv->my_hostname,
            max_value);
    else
        result = snprintf(buf, sizeof buf,
            "%s; x-hashcash=policy (%s)", priv->my_hostname,
            max_value == -1 ? "futuristic" : "expired");

    if (result < 0) {
        syslog(LOG_ERR, "%s: internal error: snprintf() failed",
               priv->queue_id);
        return;
    }
    if (buf[sizeof buf-2]) {
        syslog(LOG_NOTICE, "%s: skipped Authentication-Results header "
               "that exceeds 998 character limit", priv->queue_id);
        return;
    }

    if (smfi_insheader(ctx, ++priv->auth_results_pos,
                        header_auth_results, buf) == MI_FAILURE)
        syslog(LOG_ERR, "%s: smfi_insheader() failed", priv->queue_id);
}


sfsistat hcfi_eom(SMFICTX* ctx) {
    const struct integer* pos;
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    /* store queue ID and local hostname */
    get_syms(ctx);

    if (!priv->ignore)
        if (priv->mode == 1)
            hcfi_eom_mint(ctx);
        else if (priv->mode == 2)
            hcfi_eom_check(ctx);

    if (priv->mode != 1)
        for (pos = priv->remove_auth_results; pos != NULL; pos = pos->next)
            if (smfi_chgheader(ctx, header_auth_results, pos->integer,
                               NULL) == MI_FAILURE)
                syslog(LOG_ERR, "%s: smfi_chgheader() failed", priv->queue_id);

    if (priv->mode != 2 && priv->remove_hashcash >= 0)
        if (smfi_chgheader(ctx,
                           header_hashcash + (priv->remove_hashcash ? 0 : 2),
                           priv->hashcash_count[priv->remove_hashcash],
                           NULL) == MI_FAILURE)
            syslog(LOG_ERR, "%s: smfi_chgheader() failed", priv->queue_id);

    return SMFIS_ACCEPT;
}

sfsistat hcfi_close(SMFICTX* ctx) {
    struct hcfi_priv* priv = smfi_getpriv(ctx);

    if (priv != NULL) {
        if (priv->queue_id != null_queue_id)
            free(priv->queue_id);
        free(priv->my_hostname);
        free_strings(priv->env_rcpts);
        free_strings(priv->msg_rcpts);
        free_strings(priv->tokens);
        free_integers(priv->remove_auth_results);
        free(priv);
        if (smfi_setpriv(ctx, NULL) == MI_FAILURE) {
            syslog(LOG_ERR, "smfi_setpriv() failed");
            return SMFIS_ACCEPT;
        }
    }
    return SMFIS_CONTINUE;
}

sfsistat hcfi_negotiate(SMFICTX* ctx, unsigned long f0, unsigned long f1,
        unsigned long f2, unsigned long f3, unsigned long* pf0,
        unsigned long* pf1, unsigned long* pf2, unsigned long* pf3) {
    if (!(f0 & SMFIF_ADDHDRS))
        syslog(LOG_ERR, "MTA doesn't allow adding headers");
    if (!(f0 & SMFIF_CHGHDRS))
        syslog(LOG_ERR, "MTA doesn't allow changing or removing headers");
    *pf0 = SMFIF_ADDHDRS | SMFIF_CHGHDRS;
    *pf1 = f1 & (SMFIP_NOHELO | SMFIP_NOEOH | SMFIP_NOBODY |
                 SMFIP_NOUNKNOWN | SMFIP_NODATA);
    *pf2 = 0;
    *pf3 = 0;

    if (f0 & SMFIF_SETSYMLIST) {
        *pf0 |= SMFIF_SETSYMLIST;
        if (smfi_setsymlist(ctx,
                            SMFIM_ENVFROM, "i j {auth_type}") == MI_FAILURE |
                smfi_setsymlist(ctx, SMFIM_ENVRCPT, "i j") == MI_FAILURE |
                smfi_setsymlist(ctx, SMFIM_EOM, "i j") == MI_FAILURE)
            syslog(LOG_ERR, "smfi_setsymlist() failed");
    }
    return SMFIS_CONTINUE;
}

struct smfiDesc milter = {
    "hashcash-milter",
    SMFI_VERSION,
    SMFIF_ADDHDRS | SMFIF_SETSYMLIST,
    hcfi_connect,
    NULL,
    hcfi_envfrom,
    hcfi_envrcpt,
    hcfi_header,
    NULL,
    NULL,
    hcfi_eom,
    NULL,
    hcfi_close,
    NULL,
    NULL,
    hcfi_negotiate
};


const char* usage_short =
"Hashcash Milter 0.1.2\n"
"Usage: hashcash-milter -p socket [-f] [-P pidfile]\n"
"                      [-u user[:group] [-C rootdir]]\n"
"                      [-a] [-i addr] [-c bits [-d datafile]]\n"
"                      [-m bits [-r bits] [-s dom] [-t sec]]\n";

const char* usage_more =
"-p  listening socket:\n"
"      local:/path/to/file (relative to rootdir)\n"
"      inet:port@address\n"
"      inet6:port@address\n\n"
"-f  stay in foreground\n"
"-P  write process ID to pidfile (relative to rootdir)\n"
"-u  change user and group\n"
"-C  chroot directory\n"
"-a  mail sent after SMTP authentication is outgoing\n"
"-i  mail sent from comma-separated IP addresses or networks is outgoing\n"
"-c  check tokens on incoming messages with given minimum value\n"
"-d  storage for spent stamps (relative to rootdir)\n"
"-m  mint tokens for outgoing messages with given value\n"
"-r  reduce token value for multiple recipients to given minimum\n"
"-s  cover only mail sent from comma-separated domains\n"
"-t  maximum number of seconds to spend per message\n";


int main(int argc, char* argv[]) {
    int opt;
    int daemonize = 1;
    int status, pidfile_fd = -1, db_fd, null_fd = -1;
    long bits;
    char *arg, *end;
    char *sockfile = NULL, *user = NULL, *group = NULL, *rootdir = NULL,
         *pidfile = NULL, *datafile = NULL;
    BTREEINFO db_info;

    if (sha1_check() == -1)
        errx(EXIT_FAILURE, "internal error: SHA-1 library check failed");

    while ((opt = getopt(argc, argv, ":p:fP:u:C:ai:c:d:m:r:s:t:h")) != -1)
        switch (opt) {
        case 'p':
            if (sockfile != NULL)
                goto once;
            sockfile = strdup_checked(optarg);
            break;
        case 'f':
            if (--daemonize)
                goto once;
            break;
        case 'P':
            if (pidfile != NULL)
                goto once;
            pidfile = strdup_checked(optarg);
            break;
        case 'u':
            if (user != NULL)
                goto once;
            user = strdup_checked(optarg);
            if ((group = strchr(user, ':')) != NULL)
                *group++ = '\0';
            break;
        case 'C':
            if (rootdir != NULL)
                goto once;
            rootdir = strdup_checked(optarg);
            break;
        case 'a':
            if (cover_auth++)
                goto once;
            break;
        case 'i':
            if (cover_ipaddrs != NULL)
                goto once;
            arg = strdup_checked(optarg);
            cover_ipaddrs = parse_ipaddrs(arg); /* modifies string */
            free(arg);
            break;
        case 'c':
            bits = strtol(optarg, &end, 10);
            if (check_bits != 0)
                goto once;
            if (*end || bits <= 0 || bits > 160)
                goto invalid;
            check_bits = bits;
            break;
        case 'd':
            if (datafile != NULL)
                goto once;
            datafile = strdup_checked(optarg);
            break;
        case 'm':
            bits = strtol(optarg, &end, 10);
            if (mint_bits != 0)
                goto once;
            if (*end || bits <= 0 || bits > 160)
                goto invalid;
            mint_bits = bits;
            break;
        case 'r':
            bits = strtol(optarg, &end, 10);
            if (reduce_bits != 0)
                goto once;
            if (*end || bits <= 0 || bits > 160)
                goto invalid;
            reduce_bits = bits;
            break;
        case 's':
            if (cover_domains != NULL)
                goto once;
            arg = strdup_checked(optarg);
            cover_domains = parse_domains(arg); /* modifies string */
            free(arg);
            break;
        case 't':
            if (timeout != 0)
                goto once;
            timeout = strtol(optarg, &end, 10);
            if (*end || timeout <= 0)
                goto invalid;
            break;
        case 'h':
            printf("%s\n%s\n", usage_short, usage_more);
            return EXIT_SUCCESS;
        case ':':
            errx(EXIT_FAILURE, "-%c requires value", (char)optopt);
        case '?':
            errx(EXIT_FAILURE, "invalid option -%c", (char)optopt);
        default:
        usage:
            printf("%s\n", usage_short);
            return EXIT_FAILURE;
        once:
            errx(EXIT_FAILURE, "-%c can only be specified once", (char)opt);
        invalid:
            errx(EXIT_FAILURE, "-%c value is invalid", (char)opt);
        }

    if (sockfile == NULL) {
        if (argc == 1)
            goto usage;
        errx(EXIT_FAILURE, "-p must be specified");
    }
    if (check_bits == 0 && datafile != NULL)
        errx(EXIT_FAILURE, "-d can't be specified without -c");
    if (mint_bits != 0 && !cover_auth && cover_ipaddrs == NULL)
        errx(EXIT_FAILURE, "either -a or -i must be specified with -m");
    if (mint_bits == 0 &&
            (reduce_bits != 0 || cover_domains != NULL || timeout != 0))
        errx(EXIT_FAILURE, "-r, -s and -t can't be specified without -m");
    if (reduce_bits > mint_bits)
        errx(EXIT_FAILURE, "-r bits must be no greater than -m bits");
    if (mint_bits == 0 && check_bits == 0)
        errx(EXIT_FAILURE, "either -c or -m must be specified");
    if (rootdir != NULL && user == NULL)
        errx(EXIT_FAILURE, "-C must be specified with -u");

    /* set up before dropping privileges */
    do
        random_fd = open("/dev/urandom", O_RDONLY);
    while (random_fd == -1 && errno == EINTR);
    if (random_fd == -1)
        err(EXIT_FAILURE, "open(/dev/urandom) failed");

    if (daemonize) {
        do
            null_fd = open("/dev/null", O_RDWR);
        while (null_fd == -1 && errno == EINTR);
        if (null_fd == -1)
            err(EXIT_FAILURE, "open(/dev/null) failed");
    }

    openlog("hashcash-milter", LOG_NDELAY | LOG_PID, LOG_MAIL);

    if (pidfile != NULL) {
        do
            pidfile_fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC,
                                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        while (pidfile_fd == -1 && errno == EINTR);
        if (pidfile_fd == -1)
            err(EXIT_FAILURE, "open(%s) failed", pidfile);
        do
            status = flock(pidfile_fd, LOCK_EX | LOCK_NB);
        while (status == -1 && errno == EINTR);
        if (status == -1 && errno == EWOULDBLOCK) /* opportunistic locking */
            errx(EXIT_FAILURE, "pidfile %s is locked", pidfile);
        if (fcntl(pidfile_fd, F_SETFD, FD_CLOEXEC) == -1)
            err(EXIT_FAILURE, "fcntl(F_SETFD) failed");
    }

    /* drop privileges and change root */
    if (rootdir != NULL)
        chuid(*user ? user : NULL, group, rootdir);

    /* set up after dropping privileges */
    if (datafile != NULL) {
        if (rootdir != NULL)
            rootdir_path(datafile, rootdir);

        if ((status = pthread_mutex_init(&db_mutex, NULL)) != 0)
            errx(EXIT_FAILURE,
                 "pthread_mutex_init() failed: %s", strerror(status));

        memset(&db_info, 0, sizeof db_info);
        db_info.minkeypage = 8;
        db_info.compare = NULL;
        db_info.prefix = NULL;
        do
            db_spent = dbopen(datafile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR,
                              DB_BTREE, &db_info);
        while (db_spent == NULL && errno == EINTR);
        if (db_spent == NULL)
            err(EXIT_FAILURE, "dbopen() failed");
        if ((db_fd = db_spent->fd(db_spent)) == -1)
            err(EXIT_FAILURE, "db->fd() failed");
        do
            status = flock(db_fd, LOCK_EX | LOCK_NB);
        while (status == -1 && errno == EINTR);
        if (status == -1 && errno == EWOULDBLOCK) /* opportunistic locking */
            errx(EXIT_FAILURE, "datafile %s is locked", datafile);
        if (fcntl(db_fd, F_SETFD, FD_CLOEXEC) == -1)
            err(EXIT_FAILURE, "fcntl(F_SETFD, FD_CLOEXEC) failed");
    }

    if (rootdir != NULL && !strncmp(sockfile, "local:", 6))
        rootdir_path(sockfile + 6, rootdir);

    if (smfi_register(milter) == MI_FAILURE)
        errx(EXIT_FAILURE, "smfi_register() failed");

    if (smfi_setconn(sockfile) == MI_FAILURE)
        errx(EXIT_FAILURE, "smfi_setconn(%s) failed", sockfile);

    if (smfi_opensocket(1) == MI_FAILURE)
        errx(EXIT_FAILURE, "smfi_opensocket(%s) failed", sockfile);

    /* run daemon */
    if (daemonize && daemon(0, 1) == -1)
        err(EXIT_FAILURE, "daemon() failed");

    if (null_fd != -1)
        close_stdio(null_fd);

    if (pidfile_fd != -1 && write_long(pidfile_fd, getpid()) == -1)
        if (!daemonize)
            err(EXIT_FAILURE, "write(%s) failed", pidfile);

    syslog(LOG_INFO, "hashcash-milter 0.1.2 started");
    status = smfi_main();

    /* clean up */
    if (datafile != NULL && db_spent->close(db_spent) == -1)
        if (!daemonize)
            err(EXIT_FAILURE, "db->close() failed");

    if (pidfile_fd != -1 && ftruncate(pidfile_fd, 0) == -1)
        if (!daemonize)
            err(EXIT_FAILURE, "ftruncate(%s) failed", pidfile);

    if (pidfile != NULL && rootdir == NULL && unlink(pidfile) == -1)
        if (!daemonize)
            err(EXIT_FAILURE, "unlink(%s) failed", pidfile);

    syslog(LOG_INFO, "hashcash-milter stopped");
    return status != MI_FAILURE ? EXIT_SUCCESS : EXIT_FAILURE;
}
