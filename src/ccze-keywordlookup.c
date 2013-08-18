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

struct _keyword_t {
    char * word;
    size_t word_len;
    ccze_color_t color;
};

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

static void sort_keywords(keywords_t * K)
{
    size_t i;
    if (K->keywords_sorted)
        return;
    for (i = 0; i < 255; i++)
        qsort(K->keywords[i], K->keywords_nr[i], sizeof(keyword_t), (__compar_fn_t)keyword_compar);
    K->keywords_sorted = 1;
}

int ccze_keyword_match_prefix(keywords_t * K, const char * word, size_t word_len, ccze_color_t * color)
{
    sort_keywords(K);

    size_t i;
    unsigned p = PAGE(word, word_len);

    keyword_t * page = K->keywords[p];

    for (i = 0; i < K->keywords_nr[p]; i++)
    {
        //printf("\n----- '%s'\n", page[i].word);
        if (word_len >= page[i].word_len && memcmp(word, page[i].word, page[i].word_len) == 0)
        {
            *color = page[i].color;
            return 1;
        }
    }
    return 0;
}

static keyword_t * keyword_match(keywords_t * K, const char * word, size_t word_len)
{
    size_t i;
    unsigned p = PAGE(word, word_len);

    keyword_t * page = K->keywords[p];

    for (i = 0; i < K->keywords_nr[p]; i++)
    {
        //printf("\n+++++ '%s'\n", page[i].word);
        if (word_len == page[i].word_len && memcmp(word, page[i].word, page[i].word_len) == 0)
        {
            return &page[i];
        }
    }
    return NULL;
}

int ccze_keyword_match(keywords_t * K, const char * word, size_t word_len, ccze_color_t * color)
{
    keyword_t * k = keyword_match(K, word, word_len);
    if (k)
    {
        *color = k->color;
        return 1;
    }
    return 0;
}

void ccze_keyword_add(keywords_t * K, const char ** words, size_t words_nr, ccze_color_t color)
{
    size_t i;

    if (words_nr == 1)
    {
        size_t word_len = strlen(words[0]);
        unsigned p = PAGE(words[0], word_len);
        K->keywords[p] = realloc(K->keywords[p], (K->keywords_nr[p] + 1) * sizeof(keyword_t));
    }
    else
    {
        for (i = 0; i < 255; i++)
        {
            K->keywords[i] = realloc(K->keywords[i], (K->keywords_nr[i] + words_nr) * sizeof(keyword_t));
        }
    }

    for (i = 0; i < words_nr; i++)
    {
        size_t word_len = strlen(words[i]);

        keyword_t * k1 = keyword_match(K, words[i], word_len);
        if (k1)
        {
            k1->color = color;
        }
        else
        {
            unsigned p = PAGE(words[i], word_len);
            keyword_t * k2 = K->keywords[p] + K->keywords_nr[p];
            K->keywords_nr[p]++;
            k2->word = strdup(words[i]);
            k2->word_len = word_len;
            k2->color = color;
        }
    }

    K->keywords_sorted = 0;
}

void ccze_keyword_add1(keywords_t * K, const char * word, ccze_color_t color)
{
    ccze_keyword_add(K, &word, 1, color);
}

void ccze_keyword_clean(keywords_t * K)
{
    size_t i;
    for (i = 0; i < 255; i++)
    {
        size_t j;
        if (K->keywords[i])
        {
            for (j = 0; j < K->keywords_nr[i]; j++)
            {
                if (K->keywords[i][j].word);
                    free(K->keywords[i][j].word);
            }
            free(K->keywords[i]);
        }
        K->keywords[i] = NULL;
        K->keywords_nr[i] = 0;
    }
}

