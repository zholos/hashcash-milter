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

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

extern const char alphabet[65+1];

struct ipaddr {
    struct ipaddr* next;
    union {
        struct in_addr in;
        struct in6_addr in6;
    } addr;
    int family;
    int net;
};

struct string {
    struct string* next;
    char string[];
};

struct integer {
    struct integer* next;
    uint32_t integer;
};

struct string* string_copy(const char* s);
void free_strings(struct string* s);
void free_integers(struct integer* s);

struct ipaddr* parse_ipaddrs(char* list);
int match_ipaddr(void* hostaddr, const struct ipaddr* match);

struct string* parse_domains(char* list);
int match_domain(const char* dom, const struct string* match);

int match_address(const char* addr, const struct string* match);
struct string* find_token(const char* addr, struct string* tokens);

int parse_token(const char* value, char* token);
int token_value(const char* token, const char* date1, const char* date2);
void token_truncate(char* token);
int token_special(const char* value, const char* special);

int format_date(time_t base, long delta, char* date, size_t date_len);

int ts_delta(struct timespec* now, const struct timespec* start);

long divexp10(uint64_t x, uint64_t y, int n);

void chuid(const char* user, const char* group, const char* rootdir);
void close_stdio(int null_fd);

int write_long(int fd, long value);

char* strdup_checked(const char* s);
void rootdir_path(char* path, const char* rootdir);

#endif /* UTIL_H */
