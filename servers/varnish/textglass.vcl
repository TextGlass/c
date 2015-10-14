vcl 4.0;

import textglass;

backend default
{
  .host = "textglass.org";
  .port = "80";
}

sub vcl_deliver
{
    set resp.http.X-textglass-version = textglass.get_version();
}
