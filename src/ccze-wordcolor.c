/* -*- mode: c; c-file-style: "gnu" -*-
 * ccze-wordcolor.c -- Word-coloriser functions
 * Copyright (C) 2013 Vadim Ushakov <igeekless@gmail.com>
 * Copyright (C) 2002, 2003 Gergely Nagy <algernon@bonehunter.rulez.org>
 *
 * This file is part of ccze.
 *
 * ccze is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * ccze is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <ccze.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>

#include "ccze-private.h"
#include "ccze-compat.h"

typedef struct {
    pcre * code;
    pcre_extra * extra;
} pcre_data;

static pcre_data reg_pre, reg_post, reg_host, reg_mac, reg_email;
static pcre_data reg_uri, reg_size, reg_ver, reg_time, reg_addr;
static pcre_data reg_num, reg_sig, reg_email2, reg_hostip, reg_msgid;

static int pcre_data_exec(const pcre_data * data,
                          const char *subject, int length, int startoffset,
                          int options, int *ovector, int ovecsize)
{
    return pcre_exec(data->code, data->extra, subject, length, startoffset, options, ovector, ovecsize);
}

static void pcre_data_compile(pcre_data * data, const char *pattern, int options)
{
    const char *error;
    int errptr;
    data->code = pcre_compile(pattern, options, &error, &errptr, NULL);
    data->extra = pcre_study(data->code, PCRE_STUDY_JIT_COMPILE, &error);
}

static void pcre_data_free_fields(pcre_data * data)
{
    if (data->code)
    {
        pcre_free(data->code);
        data->code = NULL;
    }

    if (data->extra)
    {
        pcre_free_study(data->extra);
        data->extra = NULL;
    }
}


static const char *words_bad[] = {
  "warn", "restart", "exit", "stop", "end", "shutting", "down", "close",
  "unreach", "can't", "cannot", "skip", "deny", "disable", "ignored",
  "miss", "oops", "not", "backdoor", "blocking", "ignoring",
  "unable", "readonly", "offline", "terminate", "empty"
};

static const char *words_good[] = {
  "activ", "start", "ready", "online", "load", "ok", "register", "detected",
  "configured", "enable", "listen", "open", "complete", "attempt", "done",
  "check", "connect", "finish"
};

static const char *words_error[] = {
  "error", "crit", "invalid", "fail", "false", "alarm", "fatal"
};

static const char *words_system[] = {
  "ext2-fs", "reiserfs", "vfs", "iso", "isofs", "cslip", "ppp", "bsd",
  "linux", "tcp/ip", "mtrr", "pci", "isa", "scsi", "ide", "atapi",
  "bios", "cpu", "fpu", "discharging", "resume"
};


keywords_t wellknown_keywords;
keywords_t services_and_protocols_keywords;
int services_and_protocols_read = 0;


static char *
_stolower (const char *str)
{
  char *newstr = strdup (str);
  size_t i;

  for (i = 0; i < strlen (newstr); i++)
    newstr[i] = tolower (str[i]);

  return newstr;
}


static void read_services_and_protocols(void)
{
    if (services_and_protocols_read)
        return;

    setprotoent(1);
    while (1)
    {
        struct protoent * p = getprotoent();
        if (!p)
            break;
        ccze_keyword_add1(&services_and_protocols_keywords, p->p_name, CCZE_COLOR_PROT);
        char ** aliases = p->p_aliases;
        while (aliases && *aliases)
        {
            ccze_keyword_add1(&services_and_protocols_keywords, *aliases, CCZE_COLOR_PROT);
            aliases++;
        }
    }
    endprotoent();

    setservent(1);
    while (1)
    {
        struct servent * s = getservent();
        if (!s)
            break;
        ccze_keyword_add1(&services_and_protocols_keywords, s->s_name, CCZE_COLOR_SERVICE);
        char ** aliases = s->s_aliases;
        while (aliases && *aliases)
        {
            ccze_keyword_add1(&services_and_protocols_keywords, *aliases, CCZE_COLOR_SERVICE);
            aliases++;
        }
    }
    endservent();

    services_and_protocols_read = 1;
}



typedef struct {
    char * word;
    size_t size;
    ccze_color_t color;
} word_cache_t;

#define WORD_CACHE_SIZE 10
static word_cache_t word_cache[256][WORD_CACHE_SIZE];

static int word_cache_get(const char * word, size_t size, ccze_color_t * color)
{
    unsigned i;

    if (size < 1)
        return 0;

    word_cache_t * cache = word_cache[0xFF & (unsigned)word[0]];

    for (i = 0; i < WORD_CACHE_SIZE; i++)
    {
        if (cache[i].word && cache[i].size == size && memcmp(cache[i].word, word, size) == 0)
        {
            *color = cache[i].color;
            return 1;
        }
    }

    return 0;
}

static void word_cache_put(const char * word, size_t size, ccze_color_t color)
{
    if (size < 1)
        return;

    unsigned n = 0xFF & ((unsigned)word[0]);
    unsigned i = ((unsigned)rand() + size) % WORD_CACHE_SIZE;

    word_cache_t * cache = word_cache[n] + i;

    if (cache->word)
    {
        free(cache->word);
    }
    cache->word = strdup(word);
    cache->size = size;
    cache->color = color;
}


void
ccze_wordcolor_process_one (char *_word, int slookup)
{
  int offsets[99];
  ccze_color_t col;
  int match, printed = 0, put_in_cache = 1;

  const char * prefix = NULL;
  const char * postfix = NULL;

  const char * word_no_prefix = NULL;
  const char * word_no_postfix = NULL;

  const char * word = _word;

  col = CCZE_COLOR_DEFAULT;

  /** prefix **/
  if ((match = pcre_data_exec (&reg_pre, word, strlen (word), 0, 0, offsets, 99)) >= 0)
    {
      pcre_get_substring (word, offsets, match, 1, &prefix);
      pcre_get_substring (word, offsets, match, 2, &word_no_prefix);
      word = word_no_prefix;
    }

  /** postfix **/
  if ((match = pcre_data_exec (&reg_post, word, strlen (word), 0, 0, offsets, 99)) >= 0)
    {
      pcre_get_substring (word, offsets, match, 1, &word_no_postfix);
      pcre_get_substring (word, offsets, match, 2, &postfix);
      word = word_no_postfix;
    }

  char * lword = _stolower (word);
  size_t lword_len = strlen (lword);

  //printf("\n_word_=%s\n", lword);

  if (word_cache_get(lword, lword_len, &col))
    put_in_cache = 0;
  /** Host **/
  else if (pcre_data_exec (&reg_host, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_HOST;
  /** MAC address **/
  else if (pcre_data_exec (&reg_mac, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_MAC;
  /** Directory **/
  else if (lword[0] == '/')
    col = CCZE_COLOR_DIR;
  /** E-mail **/
  else if (pcre_data_exec (&reg_email, lword, lword_len, 0, 0, offsets, 99)
	   >= 0 && pcre_data_exec (&reg_email2, lword, lword_len, 0, 0,
			      offsets,99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** Message-ID **/
  else if (pcre_data_exec (&reg_msgid, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** URI **/
  else if (pcre_data_exec (&reg_uri, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_URI;
  /** Size **/
  else if (pcre_data_exec (&reg_size, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIZE;
  /** Version **/
  else if (pcre_data_exec (&reg_ver, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_VERSION;
  /** Time **/
  else if (pcre_data_exec (&reg_time, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_DATE;
  /** Address **/
  else if (pcre_data_exec (&reg_addr, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_ADDRESS;
  /** Number **/
  else if (pcre_data_exec (&reg_num, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_NUMBERS;
  /** Signal **/
  else if (pcre_data_exec (&reg_sig, lword, lword_len, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIGNAL;
  /* Host + IP (postfix) */
  else if (pcre_data_exec (&reg_hostip, lword, lword_len, 0, 0, offsets, 99) >= 0)
    {
      char *host, *ip;
      size_t hostlen, iplen;

      host = strndup (word, strchr (word, '[') - (word));
      hostlen = strlen (host);
      iplen = strlen (word) - hostlen - 1;
      ip = strndup (&word[strlen (host) + 1], iplen);
      ccze_addstr (CCZE_COLOR_HOST, host);
      ccze_addstr (CCZE_COLOR_PIDB, "[");
      ccze_addstr (CCZE_COLOR_HOST, ip);
      ccze_addstr (CCZE_COLOR_PIDB, "]");

      free (host);
      free (ip);
      printed = 1;
    }
  /* Service or procotol. */
/*  else if (slookup && getservbyname_cached (lword, NULL))
    col = CCZE_COLOR_SERVICE;
  else if (slookup && getprotobyname (lword))
    col = CCZE_COLOR_PROT;
*/
  else if (slookup && (read_services_and_protocols(), ccze_keyword_match(&services_and_protocols_keywords, lword, lword_len, &col)))
    {
      /* nothing */
    }
  /* User */
  else if (slookup && getpwnam (lword))
    col = CCZE_COLOR_USER;
  else
    { /* Good/Bad/System words */
      ccze_keyword_match_prefix(&wellknown_keywords, lword, lword_len, &col);
    }

  if (!printed)
    {
      ccze_addstr (CCZE_COLOR_DEFAULT, prefix);
      ccze_addstr (col, word);
      ccze_addstr (CCZE_COLOR_DEFAULT, postfix);
      if (put_in_cache)
        word_cache_put(lword, lword_len, col);
    }

  free (lword);
  free (_word);
  if (word_no_postfix)
      pcre_free_substring (word_no_postfix);
  if (word_no_prefix)
      pcre_free_substring (word_no_prefix);
  if (postfix)
      pcre_free_substring (postfix);
  if (prefix)
      pcre_free_substring (prefix);
}

void
ccze_wordcolor_process (const char *msg, int wcol, int slookup)
{
  char *word;
  char *msg2;

  if (msg)
    msg2 = strdup (msg);
  else
    return;

  if (!wcol)
    {
      ccze_addstr (CCZE_COLOR_DEFAULT, msg);
      free (msg2);
      return;
    }

  if ((strstr (msg, "last message repeated") && strstr (msg, "times")) ||
      (strstr (msg, "-- MARK --")))
    {
      ccze_addstr (CCZE_COLOR_REPEAT, msg);
      free (msg2);
      return;
    }

  word = xstrdup (ccze_strbrk (msg2, ' '));
  if (!word)
    {
      ccze_addstr (CCZE_COLOR_DEFAULT, msg);
      free (msg2);
      free (word);
      return;
    }
  
  do
    {
      ccze_wordcolor_process_one (word, slookup);
      ccze_space ();
    } while ((word = xstrdup (ccze_strbrk (NULL, ' '))) != NULL);

  free (msg2);
  
  return;
}

void
ccze_wordcolor_setup (void)
{
  const char *error;
  int errptr;

  pcre_data_compile (&reg_pre, "^([`'\".,!?:;(\\[{<]+)([^`'\".,!?:;(\\[{<]\\S*)$", 0);
  pcre_data_compile (&reg_post, "^(\\S*[^`'\".,!?:;)\\]}>])([`'\".,!?:;)\\]}>]+)$", 0);
  pcre_data_compile (&reg_host, "^(((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|"
			   "(([a-z0-9-_]+\\.)+[a-z]{2,3})|(localhost)|"
			   "(\\w*::\\w+)+)(:\\d{1,5})?)$", 0);
  pcre_data_compile (&reg_hostip, "^(((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|"
			     "(([a-z0-9-_\\.]+)+)|(localhost)|"
			     "(\\w*::\\w+)+)(:\\d{1,5})?)"
			     "\\[", 0);
  pcre_data_compile (&reg_mac, "^([0-9a-f]{2}:){5}[0-9a-f]{2}$", 0);
  pcre_data_compile (&reg_email, "^[a-z0-9-_=\\+]+@([a-z0-9-_\\.]+)+(\\.[a-z]{2,4})+", 0);
  pcre_data_compile (&reg_email2, "(\\.[a-z]{2,4})+$", 0);
  pcre_data_compile (&reg_uri, "^\\w{2,}:\\/\\/(\\S+\\/?)+$", 0);
  pcre_data_compile (&reg_size, "^\\d+(\\.\\d+)?[k|m|g|t]i?b?(ytes?)?", 0);
  pcre_data_compile (&reg_ver, "^v?(\\d+\\.){1}((\\d|[a-z])+\\.)*(\\d|[a-z])+$", 0);
  pcre_data_compile (&reg_time, "\\d{1,2}:\\d{1,2}(:\\d{1,2})?", 0);
  pcre_data_compile (&reg_addr, "^0x(\\d|[a-f])+$", 0);
  pcre_data_compile (&reg_num, "^-?\\d+$", 0);
  pcre_data_compile (&reg_sig, "^sig(hup|int|quit|ill|abrt|fpe|kill|segv|pipe|"
			  "alrm|term|usr1|usr2|chld|cont|stop|tstp|tin|tout|"
			  "bus|poll|prof|sys|trap|urg|vtalrm|xcpu|xfsz|iot|"
			  "emt|stkflt|io|cld|pwr|info|lost|winch|unused)", 0);
  pcre_data_compile (&reg_msgid, "^[a-z0-9-_\\.\\$=\\+]+@([a-z0-9-_\\.]+)+(\\.?[a-z]+)+", 0);

  ccze_keyword_add(&wellknown_keywords, words_bad, sizeof (words_bad) / sizeof (char *), CCZE_COLOR_BADWORD);
  ccze_keyword_add(&wellknown_keywords, words_good, sizeof (words_good) / sizeof (char *), CCZE_COLOR_GOODWORD);
  ccze_keyword_add(&wellknown_keywords, words_error, sizeof (words_error) / sizeof (char *), CCZE_COLOR_ERROR);
  ccze_keyword_add(&wellknown_keywords, words_system, sizeof (words_system) / sizeof (char *), CCZE_COLOR_SYSTEMWORD);
}

void
ccze_wordcolor_shutdown (void)
{
  pcre_data_free_fields(&reg_pre);
  pcre_data_free_fields(&reg_post);
  pcre_data_free_fields(&reg_host);
  pcre_data_free_fields(&reg_mac);
  pcre_data_free_fields(&reg_email);
  pcre_data_free_fields(&reg_email2);
  pcre_data_free_fields(&reg_uri);
  pcre_data_free_fields(&reg_size);
  pcre_data_free_fields(&reg_ver);
  pcre_data_free_fields(&reg_time);
  pcre_data_free_fields(&reg_addr);
  pcre_data_free_fields(&reg_num);
  pcre_data_free_fields(&reg_sig);
  pcre_data_free_fields(&reg_hostip);
  pcre_data_free_fields(&reg_msgid);
  ccze_keyword_clean(&wellknown_keywords);
  ccze_keyword_clean(&services_and_protocols_keywords);
  services_and_protocols_read = 0;
}
