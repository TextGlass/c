TextGlass C Client
==================

Example
-------

```c
//This is client.c

#include "textglass.h"

int main()
{
  tg_domain *domain_browser;
  tg_result *result_browser;
  char *patterns_browser = "../browser/domain/patterns.json";

  tg_domain *domain_os;
  tg_result *result_os;
  char *patterns_os = "../os/domain/patterns.json";

  char *test_string = "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";

  char buf[1024];
  size_t i;

  printf("TextGlass C Client %s\n", TEXTGLASS_VERSION);

  tg_printd_debug_level = 1;

  //load the domains

  domain_browser = tg_domain_load(patterns_browser, NULL, NULL, NULL);
  domain_os = tg_domain_load(patterns_os, NULL, NULL, NULL);

  if(!domain_browser || !domain_os)
  {
    fprintf(stderr, "Couldn't load domain\n");
    return 1;
  }

  printf("Test string: '%s'\n", test_string);

  //classify the text string

  result_browser = tg_classify(domain_browser, test_string);

  //we are storing result_os in buf
  result_os = tg_classify_fixed(domain_os, test_string, buf, sizeof(buf));

  //browser results

  if(result_browser->error_code) //fatal error
  {
    printf("Browser error: %d\n", result_browser->error_code);
  }
  else
  {
    printf("Browser result: %s\n", result_browser->pattern_id);
  }

  for(i = 0; i < result_browser->key_len; i++)
  {
    printf("Browser attribute: '%s'='%s'\n", result_browser->keys[i],
        result_browser->values[i]);
  }

  //os results

  if(result_os->error_code) //fatal error
  {
    printf("OS error: %d\n", result_os->error_code);
  }
  else
  {
    printf("OS result: %s\n", result_os->pattern_id);
  }

  for(i = 0; i < result_os->key_len; i++)
  {
    printf("OS attribute: '%s'='%s'\n", result_os->keys[i],
        tg_result_get(result_os, result_os->keys[i]));
  }

  //cleanup

  tg_result_free(result_browser);

  //we do not need to free result_os since it was stored in stack memory
  printf("OS bytes used: %zu\n", result_os->memalloc.used);

  tg_domain_free(domain_browser);
  tg_domain_free(domain_os);

  return 0;
}
```

```
> gcc -o client client.c ../c/src/libtextglass.a -I../c/src/
> ./client
TextGlass C Client 1.0.0-beta
  Pattern file: ../browser/domain/patterns.json
  Loaded pattern file, domain: browser, version: 1.0, json tokens: 438
  Found 5 tokenSeperator(s)
  Found 13 attribute(s)
  Found 19 pattern(s)
  Pattern file: ../os/domain/patterns.json
  Loaded pattern file, domain: os, version: 1.0, json tokens: 622
  Found 5 tokenSeperator(s)
  Found ngramConcatSize: 2
  Found 22 attribute(s)
  Found 34 pattern(s)
Test string: 'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2'
Browser result: chrome
Browser attribute: 'name'='Chrome'
Browser attribute: 'vendor'='Google'
Browser attribute: 'version'='15'
OS result: windowsvista
OS attribute: 'ntversion'='6.0'
OS attribute: 'version'='Vista'
OS attribute: 'name'='Windows'
OS attribute: 'vendor'='Microsoft'
OS bytes used: 0
```

