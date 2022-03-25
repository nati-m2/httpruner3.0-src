#!/usr/bin/env python
#            import !!!!
import argparse,multiprocessing,json,subprocess,os,sys,hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler

def error_log_report(Topic,error):
    log_errors = open("log_errors.txt", "a")
    log_errors.write("\n------------------------"+Topic+"------------- error num:"+str(count)+"-------------------------------")
    log = " \n" +error +"\n"
    log_errors.write(log)
    log_errors.write("-------------------------------------------------------------------------------------------------\n")
    f.close()
    return


# initializing string


count =0
f = open("httpruner config.txt", "r")
sook = f.read()
adr = sook.split(":")
if len(adr)< 4:
    error_log_report("Missing parameters"," for proper operation Please verify the httpruner config file")
    exit(-1)
hash_auth= hashlib.md5(adr[3].encode('utf-8')).hexdigest()

#
#
#
#


def parse_data(post_data):
    return json.loads(post_data)


def open_file(post_data):
    #print(post_data)
    subprocess.run(post_data, shell=True )
    return


def open_url(post_data):
    if sys.platform == "win32":
        os.startfile(post_data)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, post_data])
    return


class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()



    def _html(self, message):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        content = f" "
        return content.encode("utf8")  # NOTE: must return a bytes object!

    def do_GET(self):
        global count
        count = count + 1  # 2.1 צריך לשנות לגירסה הבאה
        self._set_headers()
        self.wfile.write(self._html("hi!"))
        if count > 20:
            exit(0)
        if self.client_address[0] != adr[2]:
            count = count + 1
            print(self.client_address[0])
        print(count)

    def do_HEAD(self):
       self._set_headers()

    def do_POST(self):
        global count
        self._set_headers()
        self.wfile.write(self._html("POST!"))
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length)  # <--- Gets the data itself
        if count > 20:
            error_log_report("Too many errors","Shutdown httpruner server")
            exit(0)
        if self.client_address[0]==adr[2]:
            Jdata=parse_data(post_data)
            try:
                if Jdata['auth']== hash_auth:
                    if Jdata['type']=="httpruer_cmd":
                        if Jdata['cmd']=="Shutdown httpruner server":
                            error_log_report("httpruer_cmd", "Shutdown httpruner server")
                            exit(0)


                    if Jdata['type']=="exec":
                        # multiprocessing
                        p = multiprocessing.Process(target=open_file, args=[Jdata['cmd']])
                        p.start()
                    elif  Jdata['type'] == "url":
                        open_url(Jdata['cmd'])
                        #print(self.client_address[0])         #<------------------- demo
                        #print(post_data)                      #<------------------- demo
                else:
                    error_log_report("incorrect hash auth code",hash_auth+"\n"+Jdata['auth'])
                    count = count + 1
            except:
                e = sys.exc_info()[0]
                error_log_report("Error: %s" % e,"Error: %s" % e)
                count = count + 1

        else:
            #print(post_data)
            count = count + 1





def run(server_class=HTTPServer, handler_class=S, addr="localhost", port=8000):
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run a simple HTTP server")
    parser.add_argument(
        "-l",
        "--listen",
        #default="localhost",
        default=adr[0],
        help="Specify the IP address on which the server listens",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=adr[1],
        help="Specify the port on which the server listens",
    )
    args = parser.parse_args()
    run(addr=args.listen, port=args.port)
    exit(0)