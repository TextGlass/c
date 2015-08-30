/*
 * Copyright (c) 2015 TextGlass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "textglass.h"

int tg_printd_debug_level = 1;

void tg_printd(int level, const char* fmt, ...)
{
#if TG_DEBUG_LOGGING
	va_list ap;

	if(level <= tg_printd_debug_level)
	{
		while(level-- > 0)
		{
			printf("  ");
		}

		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
#endif
}

void tg_time_diff(struct timespec *end, struct timespec *start, struct timespec *result)
{
	assert(end && start && result);

	result->tv_sec = end->tv_sec - start->tv_sec;
	result->tv_nsec = end->tv_nsec - start->tv_nsec;

	if(result->tv_nsec < 0)
	{
		result->tv_sec--;
		result->tv_nsec += (1000 * 1000 * 1000);
	}
}

void tg_split(char *source, size_t source_len, const char **seps, long sep_length, tg_list *tokens)
{
	size_t source_pos = 0;
	size_t dest_start = 0;
	size_t dest_end = 0;
	size_t i, j;
	const char *sep;

	assert(tokens && tokens->magic == TG_LIST_MAGIC);

	if(!seps || !sep_length)
	{
		tg_list_add(tokens, source);
		return;
	}

source:
	while(source_pos < source_len)
	{
		i = 0;
seperator:
		for(; i < sep_length; i++)
		{
			sep = seps[i];

			for(j = 0; sep[j]; j++)
			{
				if(source_pos + j >= source_len || source[source_pos + j] != sep[j])
				{
					i++;
					goto seperator;
				}
			}

			if(dest_end - dest_start > 0)
			{
				source[dest_end] = '\0';
				tg_list_add(tokens, source + dest_start);
			}

			source_pos += j;
			dest_start = dest_end = source_pos;

			goto source;
		}

		source_pos++;
		dest_end++;
	}

	if(dest_end - dest_start > 0)
	{
		source[dest_end] = '\0';
		tg_list_add(tokens, source + dest_start);
	}
}
