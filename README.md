TextGlass C Client
==================

Example
-------

```c
//This is client.c

#include "textglass.h"

int main()
{
  tg_domain *domain;
  tg_result *result;
  char *patterns = "../browser/domain/patterns.json";
  char *test_string = "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";
  size_t i;

  printf("TextGlass C Client %s\n", TEXTGLASS_VERSION);

  tg_printd_debug_level = 1;

  domain = tg_domain_load(patterns, NULL, NULL, NULL);

  if(!domain)
  {
    fprintf(stderr, "Couldn't load domain\n");
    return 1;
  }

  result = tg_classify(domain, test_string);

  if(result->error_code) //fatal transformer error
  {
    printf("Test error: %d\n", result->error_code);
  }
  else
  {
    printf("Test result: %s\n", result->pattern_id);
  }

  for(i = 0; i < result->key_len; i++)
  {
    printf("Test attribute: '%s'='%s'\n", result->keys[i], result->values[i]);
  }

  tg_result_free(result);
  tg_domain_free(domain);

  return 0;
}
```

```
> gcc -o client client.c ../c/src/libtextglass.a -I../c/src/ -I../c/src/data -I../c/src/jsmn
> ./client
TextGlass C Client 1.0.0 alpha
  Pattern file: ../browser/domain/patterns.json
  Loaded pattern file, domain: browser, version: 1.0, json tokens: 380
  Found 5 tokenSeperator(s)
  Found 11 attribute(s)
  Found 16 pattern(s)
Test result: chrome
Test attribute: 'name'='Chrome'
Test attribute: 'vendor'='Google'
Test attribute: 'version'='15'
```

