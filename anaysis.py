#coding=utf-8
#coding by linquid <<N5f0[us>>
import dpkt,sys,os

def PacpReader(fpcap,ftxt):
    PReader = dpkt.pcap.Reader(fpcap)
    for ts,buf in PReader:
        #Read the content of Pcap
        eth = dpkt.ethernet.Ethernet(buf)
        #depart the date from frame->IP->TCP->HTTP
        ip = eth.data
        tcp = ip.data
        if(tcp >0):
            try:
                data = dpkt.http.Request(tcp.data)
                #data = dpkt.http.Response(tcp.data)
                #this meaning anaysis the Response of Server
               # print data

            except:
                pass
                continue
            test = str(data)
            #control the output stream ,makes the post change a line
            if ('POST' in test ):
                test = "\n"+test+"\n\n"
            ftxt.write(test)
            ftxt.flush()
    ftxt.close()

if __name__ == '__main__':
    judge = len(sys.argv)
    if judge <= 2 or judge >3:
        print "anaysis.py c:\\test.pcap c:\\result.txt"
        exit()
    Pcap = sys.argv[1]
    #PATH = "c:\\Users\\Linquid\\Desktop\\"
    try:
        fpcap = open(Pcap,'rb')
        ftxt = open(sys.argv[2],'w')
    except :
        print "File Operate Error!"
        pass
    PacpReader(fpcap,ftxt)