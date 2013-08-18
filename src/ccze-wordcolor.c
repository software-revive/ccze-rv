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

static pcre *reg_pre, *reg_post, *reg_host, *reg_mac, *reg_email;
static pcre *reg_uri, *reg_size, *reg_ver, *reg_time, *reg_addr;
static pcre *reg_num, *reg_sig, *reg_email2, *reg_hostip, *reg_msgid;

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
  if ((match = pcre_exec (reg_pre, NULL, word, strlen (word), 0, 0,
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
  if ((match = pcre_exec (reg_post, NULL, word, strlen (word), 0, 0,
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
  if (pcre_exec (reg_host, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_HOST;
  /** MAC address **/
  else if (pcre_exec (reg_mac, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_MAC;
  /** Directory **/
  else if (lword[0] == '/')
    col = CCZE_COLOR_DIR;
  /** E-mail **/
  else if (pcre_exec (reg_email, NULL, lword, wlen, 0, 0, offsets, 99)
	   >= 0 && pcre_exec (reg_email2, NULL, lword, wlen, 0, 0,
			      offsets,99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** Message-ID **/
  else if (pcre_exec (reg_msgid, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_EMAIL;
  /** URI **/
  else if (pcre_exec (reg_uri, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_URI;
  /** Size **/
  else if (pcre_exec (reg_size, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIZE;
  /** Version **/
  else if (pcre_exec (reg_ver, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_VERSION;
  /** Time **/
  else if (pcre_exec (reg_time, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_DATE;
  /** Address **/
  else if (pcre_exec (reg_addr, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_ADDRESS;
  /** Number **/
  else if (pcre_exec (reg_num, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_NUMBERS;
  /** Signal **/
  else if (pcre_exec (reg_sig, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
    col = CCZE_COLOR_SIGNAL;
  /* Host + IP (postfix) */
  else if (pcre_exec (reg_hostip, NULL, lword, wlen, 0, 0, offsets, 99) >= 0)
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

  reg_pre = pcre_compile ("^([`'\".,!?:;(\\[{<]+)([^`'\".,!?:;(\\[{<]\\S*)$",
			  0, &error, &errptr, NULL);
  reg_post = pcre_compile ("^(\\S*[^`'\".,!?:;)\\]}>])([`'\".,!?:;)\\]}>]+)$",
			   0, &error, &errptr, NULL);
  reg_host = pcre_compile ("^(((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|"
			   "(([a-z0-9-_]+\\.)+[a-z]{2,3})|(localhost)|"
			   "(\\w*::\\w+)+)(:\\d{1,5})?)$", 0, &error,
			   &errptr, NULL);
  reg_hostip = pcre_compile ("^(((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|"
			     "(([a-z0-9-_\\.]+)+)|(localhost)|"
			     "(\\w*::\\w+)+)(:\\d{1,5})?)"
			     "\\[",
			     0, &error,  &errptr, NULL);
  reg_mac = pcre_compile ("^([0-9a-f]{2}:){5}[0-9a-f]{2}$", 0, &error,
			  &errptr, NULL);
  reg_email = pcre_compile
    ("^[a-z0-9-_=\\+]+@([a-z0-9-_\\.]+)+(\\.[a-z]{2,4})+", 0,
     &error, &errptr, NULL);
  reg_email2 = pcre_compile ("(\\.[a-z]{2,4})+$", 0, &error, &errptr, NULL);
  reg_uri = pcre_compile ("^\\w{2,}:\\/\\/(\\S+\\/?)+$", 0, &error,
			  &errptr, NULL);
  reg_size = pcre_compile ("^\\d+(\\.\\d+)?[k|m|g|t]i?b?(ytes?)?",
			   0, &error, &errptr, NULL);
  reg_ver = pcre_compile ("^v?(\\d+\\.){1}((\\d|[a-z])+\\.)*(\\d|[a-z])+$",
			  0, &error, &errptr, NULL);
  reg_time = pcre_compile ("\\d{1,2}:\\d{1,2}(:\\d{1,2})?", 0, &error,
			   &errptr, NULL);
  reg_addr = pcre_compile ("^0x(\\d|[a-f])+$", 0, &error, &errptr, NULL);
  reg_num = pcre_compile ("^-?\\d+$", 0, &error, &errptr, NULL);
  reg_sig = pcre_compile ("^sig(hup|int|quit|ill|abrt|fpe|kill|segv|pipe|"
			  "alrm|term|usr1|usr2|chld|cont|stop|tstp|tin|tout|"
			  "bus|poll|prof|sys|trap|urg|vtalrm|xcpu|xfsz|iot|"
			  "emt|stkflt|io|cld|pwr|info|lost|winch|unused)", 0,
			  &error, &errptr, NULL);
  reg_msgid = pcre_compile
    ("^[a-z0-9-_\\.\\$=\\+]+@([a-z0-9-_\\.]+)+(\\.?[a-z]+)+", 0, &error,
     &errptr, NULL);
}

void
ccze_wordcolor_shutdown (void)
{
  free (reg_pre);
  free (reg_post);
  free (reg_host);
  free (reg_mac);
  free (reg_email);
  free (reg_email2);
  free (reg_uri);
  free (reg_size);
  free (reg_ver);
  free (reg_time);
  free (reg_addr);
  free (reg_num);
  free (reg_sig);
  free (reg_hostip);
  free (reg_msgid);
}
