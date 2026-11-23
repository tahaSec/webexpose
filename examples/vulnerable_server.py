"""A deliberately misconfigured local web server for trying webexpose safely.

Run:  python examples/vulnerable_server.py
Then: webexpose http://127.0.0.1:8099
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
R={"/":(200,{"Server":"Apache/2.4.29 (Ubuntu)","X-Powered-By":"PHP/7.2.1","Set-Cookie":"PHPSESSID=abc123; path=/"},b"<h1>My shop</h1>"),
 "/.git/HEAD":(200,{},b"ref: refs/heads/main\n"),"/.env":(200,{},b"APP_ENV=production\nDB_PASSWORD=supersecret\n")}
class H(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        st,h,b=R.get(self.path,(404,{},b"nf"))
        self.send_response(st)
        for k,v in h.items(): self.send_header(k,v)
        o=self.headers.get("Origin")
        if o: self.send_header("Access-Control-Allow-Origin",o); self.send_header("Access-Control-Allow-Credentials","true")
        self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(("127.0.0.1",8099),H).serve_forever()
