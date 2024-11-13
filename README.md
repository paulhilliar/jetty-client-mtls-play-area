# jetty-client-mtls-play-area
Example of using mTLS to programatically validate client certificates in Jetty server

Developed from the base project kindly provided at https://github.com/lawrenceching/jetty-mtls-example while trying to
solve this question https://github.com/jetty/jetty.project/issues/12519 which is
"Jetty Client mTLS - How to get hold of the request URL when SSL handshake failed"

This project shows how to let clients establish a connection and then optionally validate the client certificate
on the request hot path.

Big thank you to the brilliant "SSLContext Kickstart" library at https://github.com/Hakky54/sslcontext-kickstart which
makes SSL so much easier.


### Solution overview:

No need for SslHandshakeListener

Set SslContextFactory.Server.setWantClientAuth(true); (grabs client cert if present)

Set SslContextFactory.Server.setNeedClientAuth(false); (if no client cert then establish a connection anyway)

Override the trust manager with a 'trust anything' trust manager (if client cert then trust it no matter what)

SSL Session will be negotiated and any client cert present will be 'trusted' enough to make a SSL connection

Use SecureRequestCustomizer so that the SSL session ends up in the request

Handler gets the SSL session from the request and (if appropriate for that URL) validates it using the 'real' trust manager. If there is no client cert or an untrusted client cert then it gets rejected at this point with 401/connection:close response header.

