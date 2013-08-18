/* -*- mode: c; c-file-style: "gnu" -*-
 * ccze-wordcolor.c -- Word-coloriser functions
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
  "check", "listen", "connect", "finish"
};

static const char *words_error[] = {
  "error", "crit", "invalid", "fail", "false", "alarm", "fatal"
};

static const char *words_system[] = {
  "ext2-fs", "reiserfs", "vfs", "iso", "isofs", "cslip", "ppp", "bsd",
  "linux", "tcp/ip", "mtrr", "pci", "isa", "scsi", "ide", "atapi",
  "bios", "cpu", "fpu", "discharging", "resume"
};

static size_t * words_bad_sizes = NULL;
static size_t * words_good_sizes = NULL;
static size_t * words_error_sizes = NULL;
static size_t * words_system_sizes = NULL;


static void initialize_word_sizes(void)
{
    size_t i;
    #define INIT_SIZES(n) \
        if (!words_##n##_sizes)\
        {\
            words_##n##_sizes = calloc(sizeof (words_##n) / sizeof (char *), sizeof(size_t));\
            for (i = 0; i < sizeof (words_##n) / sizeof (char *); i++)\
            {\
                words_##n##_sizes[i] = strlen(words_##n[i]);\
            }\
        }

    INIT_SIZES(bad);
    INIT_SIZES(good);
    INIT_SIZES(error);
    INIT_SIZES(system);

    #undef INIT_SIZES
}

static int match_word_list(const char ** words, size_t * word_sizes, size_t words_nr, const char * str, size_t str_len)
{
    size_t i;

    for (i = 0; i < words_nr; i++)
    {
        if (str_len >= word_sizes[i] && memcmp(str, words[i], word_sizes[i]) == 0)
            return 1;
    }
    return 0;
}


static char *
_stolower (const char *str)
{
  char *newstr = strdup (str);
  size_t i;

  for (i = 0; i < strlen (newstr); i++)
    newstr[i] = tolower (str[i]);

  return newstr;
}


/*
    Seems that getservbyname is very slow, so we use cache.
*/

typedef struct {
    char * name;
    struct servent * entry;
} getservbyname_cache_t;

#define GETSERVBYNAME_CACHE_SIZE 500
static getservbyname_cache_t getservbyname_cache[GETSERVBYNAME_CACHE_SIZE];

static struct servent *getservbyname_cached(const char *name, const char *proto)
{
    int i;

    //fprintf(stderr, "\n => %s\n", name);

    if (strlen(name) < 2)
        return NULL;
    if (!(
        (name[0] >= 'a' && name[0] <= 'z') ||
        (name[0] >= '0' && name[0] <= '9')
    ))
        return NULL;

    //fprintf(stderr, "\n +> %s\n", name);

    if (proto)
        return getservbyname(name, proto);

    for (i = 0; i < GETSERVBYNAME_CACHE_SIZE; i++)
    {
        if (getservbyname_cache[i].name && strcmp(getservbyname_cache[i].name, name) == 0)
            return getservbyname_cache[i].entry;
    }

    i = (rand() + strlen(name)) % GETSERVBYNAME_CACHE_SIZE;
    if (getservbyname_cache[i].name)
        free(getservbyname_cache[i].name);
    getservbyname_cache[i].name = strdup(name);
    getservbyname_cache[i].entry = getservbyname(name, NULL);

    return getservbyname_cache[i].entry;
}


void
ccze_wordcolor_process_one (char *word, int slookup)
{
  size_t wlen;
  int offsets[99];
  ccze_color_t col;
  int match, printed = 0;
  char *pre = NULL, *post = NULL, *tmp, *lword;

  col = CCZE_COLOR_DEFAULT;

  /** prefix **/
  if ((match = pcre_data_exec (&reg_pre, word, strlen (word), 0, 0,
			  offsets, 99)) >= 0)
    {
      pcre_get_substring (word, offsets, match, 1, (const char **)&pre);
      pcre_get_substring (word, offsets, match, 2, (const char **)&tmp);
      free (word);
      word = tmp;
    }
  else
    pre = NULL;

  /** postfix **/
  if ((match = pcre_data_exec (&reg_post, word, strlen (word), 0, 0,
			  offsets, 99)) >= 0)
    {
      pcre_get_substring (word, offsets, match, 1, (const char **)&tmp);
      pcre_get_substring (word, offsets, match, 2, (const char **)&post);
      free (word);
      word = tmp;
    }
  else
    post = NULL;

  wlen = strlen (word);
  lword = _stolower (word);

  /** Host **/
  if (pcre_data_exec (&reg_host, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_HOST;
  /** MAC address **/
  else if (pcre_data_exec (&reg_mac, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_MAC;
  /** Directory **/
  else if (lword[0] == '/')
    col = CCZE_COLOR_DIR;
  /** E-mail **/
  else if (pcre_data_exec (&reg_email, lword, wlen, 0, 0, offsets, 99)
	   >= 0 && pcre_data_exec (&reg_email2, lword, wlen, 0, 0,
			      offsets,99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** Message-ID **/
  else if (pcre_data_exec (&reg_msgid, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** URI **/
  else if (pcre_data_exec (&reg_uri, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_URI;
  /** Size **/
  else if (pcre_data_exec (&reg_size, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIZE;
  /** Version **/
  else if (pcre_data_exec (&reg_ver, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_VERSION;
  /** Time **/
  else if (pcre_data_exec (&reg_time, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_DATE;
  /** Address **/
  else if (pcre_data_exec (&reg_addr, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_ADDRESS;
  /** Number **/
  else if (pcre_data_exec (&reg_num, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_NUMBERS;
  /** Signal **/
  else if (pcre_data_exec (&reg_sig, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIGNAL;
  /* Host + IP (postfix) */
  else if (pcre_data_exec (&reg_hostip, lword, wlen, 0, 0, offsets, 99) >= 0)
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
  /* Service */
  else if (slookup && getservbyname_cached (lword, NULL))
    col = CCZE_COLOR_SERVICE;
  /* Protocol */
  else if (slookup && getprotobyname (lword))
    col = CCZE_COLOR_PROT;
  /* User */
  else if (slookup && getpwnam (lword))
    col = CCZE_COLOR_USER;
  else
    { /* Good/Bad/System words */
      size_t i;

      initialize_word_sizes();

      if (match_word_list(words_bad, words_bad_sizes, sizeof (words_bad) / sizeof (char *), lword, wlen))
        col = CCZE_COLOR_BADWORD;
      else if (match_word_list(words_good, words_good_sizes, sizeof (words_good) / sizeof (char *), lword, wlen))
        col = CCZE_COLOR_GOODWORD;
      else if (match_word_list(words_error, words_error_sizes, sizeof (words_error) / sizeof (char *), lword, wlen))
        col = CCZE_COLOR_ERROR;
      else if (match_word_list(words_system, words_system_sizes, sizeof (words_system) / sizeof (char *), lword, wlen))
        col = CCZE_COLOR_SYSTEMWORD;
    }

  if (!printed)
    {
      ccze_addstr (CCZE_COLOR_DEFAULT, pre);
      ccze_addstr (col, word);
      ccze_addstr (CCZE_COLOR_DEFAULT, post);
    }

  free (lword);
  free (word);
  free (post);
  free (pre);
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
}
