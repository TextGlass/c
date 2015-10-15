vcl 4.0;

import textglass;

backend default
{
  .host = "textglass.org";
  .port = "80";
}

sub vcl_init
{
    textglass.init_domain(0, "/etc/textglass/browser/domain/patterns.json", "");
    textglass.init_domain(1, "/etc/textglass/os/domain/patterns.json", "");
}

sub vcl_deliver
{
    textglass.classify(0, req.http.user-agent);
    set resp.http.X-textglass-browser = textglass.get_attribute(0, "name");

    textglass.classify(1, req.http.user-agent);
    set resp.http.X-textglass-os = textglass.get_attribute(1, "name");

    set resp.http.X-textglass-version = textglass.get_version();
}
