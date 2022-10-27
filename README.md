# Cookie-Security

## Cookie Security: Cookie not Sent Over SSL

### Abstract
The program creates a cookie without setting the Secure flag to True
### Explanation
Modern web browsers support a Secure flag for each cookie. If the flag is set, the browser will only send the cookie over HTTPS. Sending cookies over an unencrypted channel can expose them to network sniffing attacks, so the secure flag helps keep a cookie's value confidential. This is especially important if the cookie contains private data or session identifiers, or carries a CSRF token.
Example 1: The following code adds a cookie to the response without setting the Secure flag.
```
from django.http.response import HttpResponse
...
def view_method(request):
  res = HttpResponse()
  res.set_cookie("emailCookie", email)
  return res
...
```

If an application uses both HTTPS and HTTP, but does not set the Secure flag, cookies sent during an HTTPS request will also be sent during subsequent HTTP requests. Attackers may then compromise the cookie by sniffing the unencrypted network traffic, which is particularly easy over wireless networks.


## Cookie Security: CSRF Cookie not Sent Over SSL

### Abstract
The program does not explicitly set the CSRF_COOKIE_SECURE property to True or set it to False.
### Explanation
Modern web browsers support a Secure flag for each cookie. If the flag is set, the browser will only send the cookie over HTTPS. Sending cookies over an unencrypted channel can expose them to network sniffing attacks, so the secure flag helps keep a cookie's value confidential. This is especially important if the cookie contains private data, session identifiers, or carries a CSRF token.
Example 1: The following configuration entry does not explicitly set the Secure bit for CSRF cookies.
```
...
MIDDLEWARE_CLASSES = (
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'csp.middleware.CSPMiddleware',
    'django.middleware.security.SecurityMiddleware',
    ...
)
...
```

If an application uses both HTTPS and HTTP, but does not set the Secure flag, cookies sent during an HTTPS request will also be sent during subsequent HTTP requests. Attackers may then compromise the cookie by sniffing the unencrypted network traffic, which is particularly easy over wireless networks.

## Cookie Security: HTTPOnly not Set

### Abstract
The program creates a cookie, but fails to set the HttpOnly flag to True.
### Explanation
Browsers support the HttpOnly cookie property that prevents client-side scripts from accessing the cookie. Cross-site scripting attacks often access cookies in an attempt to steal session identifiers or authentication tokens. Without HttpOnly enabled, attackers have easier access to user cookies.
Example 1: The following code creates a cookie without setting the HttpOnly property.
```
from django.http.response import HttpResponse
...
def view_method(request):
  res = HttpResponse()
  res.set_cookie("emailCookie", email)
  return res
...
```


## Cookie Security: HTTPOnly not Set on CSRF Cookie

### Abstract
The application fails to set the HttpOnly flag to true for CSRF cookies.
### Explanation
Browsers support the HttpOnly cookie property that prevents client-side scripts from accessing the cookie. Cross-site scripting attacks often access cookies in an attempt to steal session identifiers or authentication tokens. Without HttpOnly enabled, attackers have easier access to user cookies.

Example 1: When using the django.middleware.csrf.CsrfViewMiddleware Django middleware, CSRF cookies are sent without setting the HttpOnly property.
```
...
MIDDLEWARE_CLASSES = (
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'csp.middleware.CSPMiddleware',
    'django.middleware.security.SecurityMiddleware',
    ...
)
...
```


## Cookie Security: HTTPOnly not Set on Session Cookie

### Abstract
The application fails to set the HttpOnly flag to true for session cookies.
### Explanation
Browsers support the HttpOnly cookie property that prevents client-side scripts from accessing the cookie. Cross-site scripting attacks often access cookies in an attempt to steal session identifiers or authentication tokens. Without HttpOnly enabled, attackers have easier access to user cookies.

Example 1: The following settings configuration explicitly sets the session cookies without setting the HttpOnly property.
```
...
MIDDLEWARE_CLASSES = (
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'csp.middleware.CSPMiddleware',
    'django.middleware.security.SecurityMiddleware',
    ...
)
...
SESSION_COOKIE_HTTPONLY = False
...
```

## Cookie Security: Missing SameSite Attribute

### Abstract
The program fails to set the SameSite attribute on session cookies.
### Explanation
Browsers automatically append cookies to every HTTP request made to the site that sets the cookie. Cookies might store sensitive data such as session ID and authorization token or site data that is shared between different requests to the same site during a session. An attacker can perform an impersonation attack by generating a request to the authenticated site from a third-party site page loaded on the client machine because the browser automatically appended the cookie to the request.

The samesite parameter limits the scope of the cookie so that it is only attached to a request if the request is generated from first-party or same-site context. This helps to protect cookies from Cross-Site Request Forgery (CSRF) attacks. The samesite parameter can have the following three values:

- Strict: When set to Strict, cookies are only sent along with requests upon top-level navigation.
- Lax: When set to Lax, cookies are sent with top-level navigation from the same host as well as GET requests originated to the host from third-party sites. For example, suppose a third-party site has either iframe or href tags that link to the host site. If a user follows the link, the request will include the cookie.
- None: Cookies are sent in all requests made to the site within the path and domain scope set for the cookie. Requests generated due to form submissions using the POST method are also allowed to send cookies with the request.

Example 1: The following code disables the SameSite attribute for session cookies.

  ```response.set_cookie("cookie", value="samesite-none", samesite=None)```
  
  
  
## Cookie Security: Overly Broad Domain

### Abstract
A cookie with an overly broad domain opens an application to attack through other applications.
### Explanation
Developers often set cookies to be active across a base domain such as ".example.com". This exposes the cookie to all web applications on the base domain and any sub-domains. Because cookies often carry sensitive information such as session identifiers, sharing cookies across applications can cause a vulnerability in one application to compromise another application.

Example 1: Imagine you have a secure application deployed at http://secure.example.com/ and the application sets a session ID cookie with domain ".example.com" when a user logs in.

For example:
```
from django.http.response import HttpResponse
...
def view_method(request):
  res = HttpResponse()
  res.set_cookie("mySessionId", getSessionID(), domain=".example.com")
  return res
...
```

Suppose you have another, less secure, application at http://insecure.example.com/, and it contains a cross-site scripting vulnerability. Any user authenticated to http://secure.example.com that browses to http://insecure.example.com risks exposing their session cookie from http://secure.example.com.

In addition to reading a cookie, it might be possible for attackers to perform a "Cookie poisoning attack" by using insecure.example.com to create its own overly broad cookie that overwrites the cookie from secure.example.com.
