/*
 * Copyright (C) 2013 Vadim Ushakov <igeekless@gmail.com>
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
#include <string.h>
#include <stdlib.h>

#include "ccze-private.h"
#include "ccze-compat.h"

typedef struct {
    const char * word;
    size_t word_len;
    ccze_color_t color;
} keyword_t;

static keyword_t * keywords[256];
static size_t      keywords_nr[256];
static int         keywords_sorted = 0;

static unsigned PAGE(const char * word, size_t word_len)
{
    unsigned p = (unsigned) word[0];
    if (word_len > 0)
        p ^= (unsigned) word[1] * 2;
    return 0xFF & p;
}

static int keyword_compar(const keyword_t * a, const keyword_t * b)
{
    return b->word_len - a->word_len;
}

static void sort_keywords(void)
{
    size_t i;
    if (keywords_sorted)
        return;
    for (i = 0; i < 255; i++)
        qsort(keywords[i], keywords_nr[i], sizeof(keyword_t), (__compar_fn_t)keyword_compar);
    keywords_sorted = 1;
}

int ccze_keyword_match(const char * word, size_t word_len, ccze_color_t * color)
{
    sort_keywords();

    size_t i;
    unsigned p = PAGE(word, word_len);

    keyword_t * page = keywords[p];

    for (i = 0; i < keywords_nr[p]; i++)
    {
        if (word_len >= page[i].word_len && memcmp(word, page[i].word, page[i].word_len) == 0)
        {
            *color = page[i].color;
            return 1;
        }
    }
    return 0;
}

void ccze_keyword_add(const char ** words, size_t words_nr, ccze_color_t color)
{
    size_t i;

    for (i = 0; i < 255; i++)
    {
        keywords[i] = realloc(keywords[i], (keywords_nr[i] + words_nr) * sizeof(keyword_t));
    }

    for (i = 0; i < words_nr; i++)
    {
        size_t word_len = strlen(words[i]);
        unsigned p = PAGE(words[i], word_len);
        keyword_t * keyword = keywords[p] + (keywords_nr[p]++);
        keyword->word = words[i];
        keyword->word_len = word_len;
        keyword->color = color;
    }

    keywords_sorted = 0;
}

void ccze_keyword_clean(void)
{
    size_t i;
    for (i = 0; i < 255; i++)
    {
        if (keywords[i])
            free(keywords[i]);
        keywords[i] = NULL;
        keywords_nr[i] = 0;
    }
}

