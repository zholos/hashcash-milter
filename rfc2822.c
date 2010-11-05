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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

const char* skip_comment(const char* s) {
    int brackets = 0;
    for (;; s++) {
        switch (*s) {
        case '\0':
            /* always succeeds,
               but accepts unfinished comment at end of input */
            return s;
        case '(':
            brackets++;
            break;
        case ')':
            if (!--brackets)
                return s + 1;
        case '\\':
            if (s[1])
                s++;
        }
    }
}

const char* skip_fws(const char* s) {
    for (; isspace(*s); s++);
    return s;
}

const char* skip_cfws(const char* s) {
    s = skip_fws(s);
    while (*s == '(')
        s = skip_fws(skip_comment(s));
    return s;
}

const char* special = "\"(),.:;<>@[\\]";

const char* skip_quoted_string(const char* s) {
    if (*s++ != '"')
        return NULL;
    for (; *s && *s != '"'; s++)
        if (*s == '\\' && s[1])
            s++;
    return *s++ == '"' ? s : NULL;
}

const char* skip_phrase(const char* s) {
    const char* t;
    s = skip_cfws(s);
    do {
        t = s;
        if (*s == '"') { /* quoted-string */
            s = skip_quoted_string(s);
            if (s == NULL)
                return NULL;
        } else if (*s == '.') /* from obs-phrase */
            s++;
        else { /* atom */
            for (; *s && !iscntrl(*s) && !isspace(*s) &&
                strchr(special, *s) == NULL; s++);
        }
        s = skip_cfws(s);
    } while (s != t);
    return s;
}

const char* parse_dot_atom_text(const char* s, char** list) {
    const char* atext_start;
    for (;;) {
        atext_start = s;
        for (; *s && !iscntrl(*s) && !isspace(*s) &&
                strchr(special, *s) == NULL; s++)
            if (list != NULL)
                *(*list)++ = *s;
        if (atext_start == s)
            return NULL;

        if (*s == '.') {
            if (list != NULL)
                *(*list)++ = *s;
            s++;
        } else
            return s;
    }
}

const char* skip_dot_atom_text(const char* s) {
    return parse_dot_atom_text(s, NULL);
}

const char* parse_quoted(char open, char close, const char* s, char** list) {
    int folding = 0;
    for (; *s && *s != close && *s != open; s++) {
        if (*s == '\\' && s[1]) {
            s++;
            goto escaped;
        }
        if (isspace(*s)) {
            if (!folding) {
                *(*list)++ = ' ';
                folding = 1;
            }
        } else {
        escaped:
            *(*list)++ = *s;
            folding = 0;
        }
    }
    if (*s++ != close)
        return NULL;
    return s;
}

const char* parse_local_domain(const char* s, char** list, int allow_comments) {
    s = allow_comments ? skip_cfws(s) : skip_fws(s);
    if (*s == '"')
        s = parse_quoted('"', '"', s + 1, list); /* quoted-string */
    else
        s = parse_dot_atom_text(s, list);
    if (s == NULL)
        return NULL;
    s = allow_comments ? skip_cfws(s) : skip_fws(s);
    *(*list)++ = '\0';

    if (*s++ != '@')
        return NULL;

    s = allow_comments ? skip_cfws(s) : skip_fws(s);
    if (*s == '[') {
        *(*list)++ = '[';
        s = parse_quoted('[', ']', s + 1, list); /* domain-literal */
        if (s != NULL)
            *(*list)++ = ']';
    } else
        s = parse_dot_atom_text(s, list);
    if (s == NULL)
        return NULL;
    s = allow_comments ? skip_cfws(s) : skip_fws(s);
    *(*list)++ = '\0';

    return s;
}

const char* parse_addr_spec(const char* s, char** list) {
    return parse_local_domain(s, list, 1);
}

const char* parse_address_list(int mailbox, const char* s, char** list);

const char* parse_address(int mailbox, const char* s, char** list) {
    const char* p;

    s = skip_cfws(s);
    p = skip_phrase(s);
    if (p == s && *p == ':')
        return NULL;
    switch (*p) {
    case ':': /* phrase was display-name of group */
        if (mailbox)
            return NULL;
        s = skip_cfws(p + 1);
        if (*s != ';')
            s = parse_address_list(1, s, list);
        if (s == NULL || *s != ';')
            return NULL;
        return skip_cfws(s + 1);
    case '<': /* phrase was display-name for address-spec */
        s = parse_addr_spec(p + 1, list);
        if (s == NULL || *s != '>')
            return NULL;
        return skip_cfws(s + 1);
    default:
        /* phrase included part of local-part */
        return parse_addr_spec(s, list);
    }
}

const char* parse_address_list(int mailbox, const char* s, char** list) {
    for (;;) {
        s = parse_address(mailbox, s, list);
        if (s == NULL)
            return NULL;
        if (*s == ',')
            s++;
        else
            return s;
    }
}

/* list must be allocated at least strlen(field)+2 characters,
   it is filled with "local\0domain\0...local\0domain\0\0"
   domains in domain-literal form retain the square brackets */
int rfc2822_address_list(const char* field, char* list) {
    const char* s = parse_address_list(0, field, &list);
    if (s == NULL || *s != '\0')
        return -1;
    else {
        *list = '\0';
        return 0;
    }
}

/* returns 1 if the given string can be represented with a dot-atom-text,
   which means that it can be the local or domain part of addr-spec unquoted,
   and that it doesn't include any whitespace */
const char* atext = "!#$%&'*+-/=?^_`{|}~";

int rfc2822_is_dot_atom_text(const char* s) {
    const char* atext_start;
    for (;;) {
        atext_start = s;
        while (*s && (isalpha(*s) || isdigit(*s) || strchr(atext, *s) != NULL))
            s++;
        if (atext_start == s)
            return 0;

        if (*s == '.')
            s++;
        else
            return *s == '\0';
    }
}


const char* parse_mailbox(const char* s, char** mailbox) {
    return parse_local_domain(s, mailbox, 0);
}

/* mailbox must be allocated at least strlen(path)+1 characters,
   sets mailbox to 'local\0domain\0' from the mailbox part of path */
int rfc5321_mailbox(const char* path, char* mailbox) {
    int angle = 0;
    const char* s = path;

    /* we accept additional whitespace,
       and also the absense of angle brackets */
    s = skip_fws(s);
    if (*s == '<') {
        angle = 1;
        s++;
    }
    s = skip_fws(s);

    /* empty reverse-path */
    if (angle ? *s == '>' && !*skip_fws(s + 1) : !*s) {
        *mailbox = '\0';
        return 0;
    }

    /* a-d-l ":" */
    if (*s == '@') {
        while (*s == '@') {
            s = skip_dot_atom_text(skip_fws(s + 1));
            if (s == NULL)
                return -1;
            s = skip_fws(s);
            if (*s == ',') {
                s = skip_fws(s + 1);
                continue;
            } else
                break;
        }
        if (*s != ':')
            return -1;
        s = skip_fws(s + 1);
    }

    /* parse mailbox as an address-spec,
       the MTA should reject what it considers invalid addresses anyway */
    s = parse_mailbox(s, &mailbox);
    if (s == NULL)
        return -1;

    if (angle && *s == '>')
        s = skip_fws(s + 1);
    return *s ? -1 : 0;
}


const char* rfc5451_parse_dot_atom_text(const char* s, char** list) {
    const char* atext_start = s;
    for (; *s == '.' ||
               *s && !iscntrl(*s) && !isspace(*s) &&
                   strchr(special, *s) == NULL && *s != '=' && *s != '/' ; s++)
        if (list != NULL)
            *(*list)++ = *s;
    return atext_start == s ? NULL : s;
}

const char* rfc5451_skip_dot_atom_text(const char* s) {
    return rfc5451_parse_dot_atom_text(s, NULL);
}

/* mailbox must be allocated at least strlen(field)+4 characters,
   sets methods to 'authserv\0version\0method\0...method\0\0',
   version is normalized by removing leading zeroes or set to default of '1';
   if -2 is returned, the authserv and version will be given and methods will
   have a partial result; the valid "none" value will also return -2 */
int rfc5451_methods(const char* field, char* methods) {
    const char* s;
    char* n;

    s = parse_dot_atom_text(skip_cfws(field), &methods); /* authserv-id */
    if (s == NULL)
        return -1;
    *methods++ = '\0';

    s = skip_cfws(s);
    if (isdigit(*s)) { /* version */
        for (; *s == '0'; s++);
        if (isdigit(*s))
            for (; isdigit(*s); s++)
                *methods++ = *s;
        else
            *methods++ = '0';
        s = skip_cfws(s);
    } else
        *methods++ = '1';
    *methods++ = '\0';

    if (*s != ';')
        goto failed;
    while (*s == ';') {
        /* resinfo */
        /* RFC 5451 allows an ambiguity here;
           we don't allow "/" and "=" in dot-atoms here to resolve it */
        n = methods;
        s = skip_cfws(s + 1);
        s = rfc5451_parse_dot_atom_text(s, &methods); /* method */
        if (s == NULL) {
            methods = n;
            goto failed;
        }
        *methods++ = '\0';

        s = skip_cfws(s);
        if (*s == '/') {
            s = skip_cfws(s + 1);
            if (!isdigit(*s))
                goto failed;
            for (; isdigit(*s); s++); /* version */
            s = skip_cfws(s);
        }

        if (*s++ != '=')
            goto failed;

        s = skip_dot_atom_text(skip_cfws(s)); /* result */
        if (s == NULL)
            goto failed;

        s = skip_cfws(s);
        for (; isalpha(*s); s = skip_cfws(s)) {
            /* reasonspec / propspec */
            /* this is will accept much */
            for (; isalpha(*s); s++); /* "reason" / ptype */

            s = skip_cfws(s);
            if (*s == '.') {
                s = rfc5451_skip_dot_atom_text(skip_cfws(s + 1)); /* property */
                if (s == NULL)
                    goto failed;
                s = skip_cfws(s);
            }
            if (*s++ != '=')
                goto failed;

            s = skip_cfws(s); /* pvalue */
            if (*s != '@') {
                s = *s == '"' ? skip_quoted_string(s) : skip_dot_atom_text(s);
                if (s == NULL)
                    goto failed;
            }
            if (*s == '@')
                s = skip_dot_atom_text(s + 1); /* domain-name */
        }
    }
    if (*s)
        goto failed;
    *methods = '\0';
    return 0;

failed:
    *methods = '\0';
    return -2;
}


#ifdef TEST
#include <stdio.h>

void print(const char* s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '"' || *s == '\\')
            printf("\\\\%c", *s);
        else if (isprint(*s))
            putchar(*s);
        else
            printf("\\\\%o", *s);
    }
    putchar('"');
}

int main() {
    char field[1024], list[1024+1];
    const char *s;

    while (fgets(field, sizeof(field), stdin) != NULL) {
        if (rfc2822_addresses(0, field, list) == -1)
            printf("failed\n");
        else {
            for (s = list; *s;) {
                print(s);
                s = strchr(s, '\0') + 1;
                if (*s) {
                    putchar('@');
                    print(s);
                    s += strlen(s) + 1;
                    if (*s)
                        printf(", ");
                }
            }
            putchar('\n');
        }
    }
    return 0;
}
#endif /* TEST */
