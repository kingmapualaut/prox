#!/usr/bin/env python3
# encoding: utf-8
# SOCKs Proxy by X-DCB
import socket, threading, _thread, select, signal, sys, time, configparser, os, re, smtplib, traceback
import urllib.request as req
os.system("clear")
recvbuff = 65536
success = b"HTTP/1.1 200 <font color=\"green\">Dexter Cellona Banawon (X-DCB)</font>\r\n\r\n"
failure = b"HTTP/1.1 404\r\n\r\n"
me=req.urlopen("http://ipv4.icanhazip.com/").read().decode("utf-8").strip()
ploc=os.path.dirname(os.path.realpath(__file__))

def mailer(msg):
	server = smtplib.SMTP('smtp.gmail.com: 587')
	server.starttls()
	msg="""\
Subject: SocksProxy

Server IP: %s
%s""" % (me, msg)
	em="mailerx0001@gmail.com"
	server.login(em,"bywqjjwxfiilidxb")
	server.sendmail('', em, msg)
	server.quit()

servers=list()
class Server(threading.Thread):
    def __init__(self, sport, dport, timer):
        threading.Thread.__init__(self)
        self.running = False
        self.host = "0.0.0.0"
        self.port = int(sport)
        self.dport=int(dport)
        self.defhost = '0.0.0.0:'+dport
        self.timer = int(timer)
        self.threads = []
        self.threadsLock = threading.Lock()
        print("Listening on port %s for port %s%s." % (sport, dport," with %ss timer" % timer if int(timer) > 30 else ''))

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
        self.soc.settimeout(3)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
                    c.setblocking(3)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            if conn in self.threads:
                self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()

def reader(loc):
     f = open(loc, 'r')
     cont=f.read()
     f.close()
     return cont

def to_b(str):
    return bytes(str, 'utf-8')

def bsplitlines(bstr):
	return re.split(b'[\r\n]+', bstr)

def parser(req):
    lines=bsplitlines(req)
    if re.match(b"^GET", lines[0]):
    	rloc=lines[0].decode('utf-8').split(' ')[1]
    	wloc=ploc+'/web'+rloc
    	if rloc == '/':
    	   wloc+='index.html'
    	return success+to_b(reader(wloc)) if os.path.exists(wloc) else failure
    return None
    	
class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ""
        self.server = server
        self.cl_addr = addr

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
        
        self.server.removeConn(self)
    
    def logfile(self, msg):
    	f = open(ploc+"/log.txt", "a")
    	f.write(msg+"\n")
    	f.close()
    
    def log_time(self, msg):
    	#print(time.strftime("[%H:%M:%S]"), msg)
    	pass
    
    def run(self):
    	sport=str(self.server.port)
    	dport=str(self.server.dport)
    	try:
            self.client_buffer = self.client.recv(recvbuff)
            buff = self.client_buffer
            
            res=parser(buff)
            if res:
            	self.client.send(res)
            	self.close()
            	return
            
            hostPort = self.server.defhost
            if b"CONNECT" in buff:
            	cc=[x for x in bsplitlines(buff) if b'CONNECT' in x][0].decode('utf-8')
            	hp=re.findall(r"[a-zA-Z0-9.-]+:\d+", cc)[0]
            	ip = socket.getaddrinfo(hp[0:hp.find(':')], 80)[0][4][0]
            	if not((sport in hp or dport in hp) and ip in ['127.0.0.1', '0.0.0.0', me]):
            		hostPort=hp

            self.log_time("client: %s - server: %s - buff: %s" % (self.cl_addr, hostPort, buff))
            
            try:
            	uhost = self.findHeader('Host', buff.decode('utf-8'))
            	if uhost == "":
            		self.log_time(self.client.recv(recvbuff))
            except:
            	pass

            self.method_CONNECT(hostPort)
    	except:
            mailer("""\
Port: %s
Buffer: %s
Traceback: %s\
""" % (sport, self.client_buffer, traceback.format_exc()))
    	finally:
            self.close()

    def findHeader(self, head, header):
    	hdr={}
    	for line in header.splitlines():
    		ls=line.split(':')
    		if len(ls) == 2:
    			hdr[ls[0].strip()]=ls[1].strip()
    	return hdr[head] if head in hdr else ""

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.target.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
        self.targetClosed = False
        self.target.connect(address)
        self.t_addr = address

    def method_CONNECT(self, path):
        self.connect_target(path)
        self.client.send(success)
        self.client_buffer = ""
        self.time_start = time.time()
        self.doCONNECT()
    
    def timer_dc(self):
    	check=int(time.time() - self.time_start) >= self.server.timer and self.server.timer >= 30
    	if check:
    		self.close()
    		self.log_time("Client disconnected (timer)")
    	return check
    
    def doCONNECT(self):
        socs = [self.client, self.target]
        error = False
        count=0
        while True:
            (recv, _, err) = select.select(socs, [], socs, 3)
            if count >= 50 or self.timer_dc():
                self.close()
                break
            if err:
                count+=1
                time.sleep(1)
            elif recv:
                for in_ in recv:
                    try:
                        data = in_.recv(recvbuff)
                        if data:
                            count=0
                            if in_ is self.target:
                                try:
                                    self.client.connect(self.cl_addr)
                                except:
                                    pass
                                self.client.send(data)
                            else:
                                try:
                                    self.target.connect(self.t_addr)
                                except Exception as e:
                                    pass
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                                if self.timer_dc():
                                	break
                        else:
                        	time.sleep(1)
                        	count+=1
                        	break
                    except:
                        count+=1
            
            

def main():
    ch=ploc+'/.firstrun'
    if not(os.path.exists(ch)):
    	open(ch, 'w').close()
    	mailer("\nSomeone is using your code.")
    pidx=str(os.getpid())
    pid=open(ploc+'/.pid', 'w')
    pid.write(pidx)
    pid.close()
    print("\033[0;34m="*8,"\033[1;32mPROXY SOCKS","\033[0;34m="*8,"\n\033[1;33m\033[1;32m")
    config = configparser.ConfigParser()
    try:
    	config.read(ploc+'/server.conf')
    	for s in config.sections():
    		c = config[s]
    		if 'sport' in c and 'timer' in c and 'dport' in c:
    			server = Server(c['sport'], c['dport'], c['timer'])
    			server.start()
    			servers.append(server)
    		else:
    			raise Exception('Missing values.')
    	print('PID:', pidx)
    except Exception as e:
    	print("Configuration error. Err:", str(e))
    finally:
    	print('\n'+"\033[0;34m="*11,"\033[1;32mX-DCB","\033[0;34m=\033[1;37m"*11,"\n")
    	while True:
    	       try:
    	       	time.sleep(2)
    	       except KeyboardInterrupt:
    	       	for svr in servers:
    	       		svr.close()
    	       	print("\nCancelled...")
    	       	exit()

if __name__ == "__main__":
    main()
