

aws-keys.json

```
grep -HanrE "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"
```


base64.json

```
grep -HnroE "([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/]+={0,2}"
```


cors.json

```
grep -HnriE "Access-Control-Allow"
```


debug-pages.json

```
grep -HnraiE "(Application-Trace|Routing Error|DEBUG\"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in `|#!/us|WebApplicationException|java\\.lang\\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE)"
```


firebase.json

```
grep -Hnri "firebaseio.com"
```


fw.json

```
grep -HnriE "django"\|"laravel"\|"symfony"\|"graphite"\|"grafana"\|"X-Drupal-Cache"\|"struts"\|"code ?igniter"\|"cake ?php"\|"grails"\|"elastic ?search"\|"kibana"\|"log ?stash"\|"tomcat"\|"jenkins"\|"hudson"\|"com.atlassian.jira"\|"Apache Subversion"\|"Chef Server"\|"RabbitMQ Management"\|"Mongo"\|"Travis CI - Enterprise"\|"BMC Remedy"\|"artifactory"
```


go-functions.json

```
grep -HnriE "func [a-z0-9_]+\\("
```


http-auth.json

```
grep -hrioaE "[a-z0-9_/\\.:-]+@[a-z0-9-]+\\.[a-z0-9.-]+"
```


ip.json

```
grep -HnroE "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
```


json-sec.json

```
grep -harioE "(\\\\?\"|&quot;|%22)[a-z0-9_-]*(api[_-]?key|S3|aws_|secret|passw|auth)[a-z0-9_-]*(\\\\?\"|&quot;|%22): ?(\\\\?\"|&quot;|%22)[^\"&]+(\\\\?\"|&quot;|%22)"
```


meg-headers.json

```
grep -hroiE "^\u003c [a-z0-9_\\-]+: .*"
```


php-curl.json

```
grep -HnrE "CURLOPT_(HTTPHEADER|HEADER|COOKIE|RANGE|REFERER|USERAGENT|PROXYHEADER)"
```


php-errors.json

```
grep -HnriE "php warning"\|"php error"\|"fatal error"\|"uncaught exception"\|"include_path"\|"undefined index"\|"undefined variable"\|"\\?php"\|"<\\?[^x]"\|"stack trace\\:"\|"expects parameter [0-9]*"\|"Debug Trace"
```


php-serialized.json

```
grep -HnrE "a:[0-9]+:{", "O:[0-9]+:\"", "s:[0-9]+:\""
```


php-sinks.json

```
grep HnriE "[^a-z0-9_](system|exec|popen|pcntl_exec|eval|create_function|unserialize|file_exists|md5_file|filemtime|filesize|assert) ?\\("
```


php-sources.json

```
grep -HnrE "\\$_(POST|GET|COOKIE|REQUEST|SERVER|FILES)"\|"php://(input|stdin)"
```


s3-buckets.json

```
grep -hrioaE "[a-z0-9.-]+\\.s3\\.amazonaws\\.com"\|"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com"\|"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)"\|"//s3\\.amazonaws\\.com/[a-z0-9._-]+"\|"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+"
```


sec.json

```
grep -HanriE "(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|aws_|secret|ssh-rsa AA)"
```


servers.json

```
grep -hri "server: "
```


strings.json

```
grep -hroiaE "\"[^\"]+\""\|"'[^']+'"
```


takeovers.json

```
grep -HnriE "There is no app configured at that hostname"\|"NoSuchBucket"\|"No Such Account"\|"You're Almost There"\|"a GitHub Pages site here"\|"There's nothing here"\|"project not found"\|"Your CNAME settings"\|"InvalidBucketName"\|"PermanentRedirect"\|"The specified bucket does not exist"\|"Repository not found"\|"Sorry, We Couldn't Find That Page"\|"The feed has not been found."\|"The thing you were looking for is no longer here, or never was"\|"Please renew your subscription"\|"There isn't a Github Pages site here."\|"We could not find what you're looking for."\|"No settings were found for this company:"\|"No such app"\|"is not a registered InCloud YouTrack"\|"Unrecognized domain"\|"project not found"\|"This UserVoice subdomain is currently available!"\|"Do you want to register"\|"Help Center Closed"
```



upload-fields.json

```
grep -HnriE "\u003cinput[^\u003e]+type=[\"']?file[\"']?"
```


urls.json

```
grep -oriahE "https?://[^\"\\'> ]+"
```
