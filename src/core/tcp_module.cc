#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <list>

#include <iostream>
#include "Minet.h"
#include "tcpstate.h"
#include "packet_queue.h"


using namespace std;

Packet SendPacket( Connection c, unsigned char flags, unsigned int seqNum,
		unsigned int ackNum, MinetHandle mux) {
	Buffer data = Buffer(NULL, 0);
    	unsigned bytes = MIN_MACRO(IP_PACKET_MAX_LENGTH-TCP_HEADER_BASE_LENGTH, 
		    data.GetSize());
    	
	Packet np(data.ExtractFront(bytes));
    
   	IPHeader iph;
    	iph.SetProtocol(IP_PROTO_TCP);
    	iph.SetSourceIP(c.src);
   	iph.SetDestIP(c.dest);
   	iph.SetTotalLength(bytes+TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
    
   	np.PushFrontHeader(iph);
    
   	TCPHeader tcph;
   	tcph.SetSourcePort(c.srcport,np);
  	tcph.SetDestPort(c.destport,np);
   	tcph.SetSeqNum(seqNum, np);
    
   	 if (IS_ACK(flags)) {
       		 tcph.SetAckNum(ackNum,np);    
    	}
    
   	 tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4,np);

  	 tcph.SetFlags(flags,np);
   	 tcph.SetWinSize(100,np);
    
    
  	 np.PushBackHeader(tcph);
    	 MinetSend(mux, np);
    
	 return np;
}

Packet SendSyn(Connection c, unsigned int seqnum, unsigned int acknum, MinetHandle mux){

    unsigned char nflags;
    SET_SYN(nflags);
    Packet np = SendPacket( c, nflags, seqnum, acknum, mux);

    return np;
}                        

Packet SendSynAck(Connection c, unsigned int seqnum, unsigned int acknum, MinetHandle mux){

    unsigned char nflags;
    SET_SYN(nflags);
    SET_ACK(nflags);
    Packet np = SendPacket( c, nflags, seqnum, acknum, mux);

    return np;
}                        


Packet SendAck(Connection c, unsigned int seqnum, unsigned int acknum, MinetHandle mux){

    unsigned char nflags;
    SET_ACK(nflags);
    Packet np = SendPacket( c, nflags, seqnum, acknum, mux);

    return np;
}     

Packet SendFin(Connection c, unsigned int seqnum, unsigned int acknum, MinetHandle mux){

    unsigned char nflags;
    SET_FIN(nflags);
    Packet np = SendPacket( c, nflags, seqnum, acknum, mux);

    return np;
}                        




void ListenFunc(list<Packet> packetq, unsigned char flags, Connection c, unsigned int currSeqNum, unsigned int ackNum, MinetHandle mux, ConnectionList<TCPState>::iterator &cs){
 	 cerr << "LISTEN: ";
        if (IS_SYN(flags)) {                           
                              cerr << "receive SYN, send SYN ACK" << endl;
                              Packet np = SendSynAck(c, currSeqNum, ackNum, mux);
		              packetq.push_back(np);
                              currSeqNum++;
                              cs->state.SetState(SYN_RCVD);
	}
}
void Syn_rcvdFunc(list<Packet> packetq, unsigned char flags, Connection c, unsigned int currSeqNum, unsigned int ackNum, MinetHandle mux, ConnectionList<TCPState>::iterator &cs){
 
	cerr << "SYN_RCVD: ";
        if (IS_ACK(flags)){
                     cerr << "receive ack, ESTABLISHED" << endl; 
		     cs->state.SetState(ESTABLISHED);
	}
}
                               
void Syn_sentFunc(list<Packet> packetq, unsigned char flags, Connection c, unsigned int currSeqNum, unsigned int ackNum, MinetHandle mux, ConnectionList<TCPState>::iterator &cs){
 		       
                           
       cerr << "SYN_SENT: ";
       if (IS_SYN(flags)) {
	       if (IS_ACK(flags)) {
		       cerr << "receive SYNACK,  send ACK and set ESTABLISHED" << endl;
                                       
                       Packet np = SendAck(c, currSeqNum, ackNum, mux);
		       packetq.push_back(np);
		       currSeqNum++;
                       cs->state.SetState(ESTABLISHED);
		       cs->state.SetLastAcked(ackNum);
               } else {
                                       cerr << "receive SYN, send ACK again" << endl;
                                      // unsigned char nflags;
                                      // SET_ACK(nflags);
                                      // Packet np = SendPacket( c, nflags, currSeqNum, ackNum, mux);
                                       
                                      Packet np = SendAck(c, currSeqNum, ackNum, mux);
				       packetq.push_back(np);
                                       currSeqNum++;
                                       cs->state.SetState(SYN_RCVD);
	       }
       }

}

int main(int argc, char *argv[]){
   
   MinetHandle mux, sock;
   unsigned int currSeqNum = 1000;
   list<Packet> packetq;
   

   ConnectionList<TCPState> clist;
   MinetInit(MINET_TCP_MODULE);
   
   mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
   sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;
   
   if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
       MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
       return -1;
   }
   
   if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
       MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
       return -1;
   }
   
   MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));
   MinetEvent event;
   
   Time timeout(1);
   
   cerr << "handling TCP traffic......" << endl;
   
   while (MinetGetNextEvent(event, timeout)==0) { 
       if (event.eventtype == MinetEvent::Timeout) {
//	       cerr << "timeout!\n";
               for (ConnectionList<TCPState>::iterator i = clist.begin(); i != clist.end(); ++i) {
                 bool expired = false;
              	 if (i->bTmrActive) 
                   expired = i->state.ExpireTimerTries();
                 cerr << "current state is " << i->state.GetState()<<endl;

		 if (expired) {
                   cerr << "timed out, set state to CLOSED" << endl;
                   i->state.SetState(CLOSED);
                   i->bTmrActive = false;
                   packetq= list<Packet>();
               } else if (i->state.GetState() == CLOSED) {
                   cerr << "CLOSED timeout, set state to LISTEN" << endl;
                   i->state.SetState(LISTEN);
                   i->bTmrActive = false;
               }
           }
       } else if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
           MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));

           // if we received a valid event from Minet, do processing
       } else {
           
           cerr << "entering main loop\n ";
           
           //  Data from the IP layer below  //
           if (event.handle==mux) {
               cerr << "Received IP packet" << endl;
               Packet receiveP;
               MinetReceive(mux,receiveP);
               unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(receiveP);
               cerr << "estimated header len="<<tcphlen<<"\n";
               receiveP.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
               IPHeader iph=receiveP.FindHeader(Headers::IPHeader);
               TCPHeader tcph=receiveP.FindHeader(Headers::TCPHeader);
               
               
             
               cerr << "IP Header is " << iph << endl;
               cerr << "TCP Header is " << tcph << endl;
               cerr << "Checksum is " << (tcph.IsCorrectChecksum(receiveP) ? "VALID" : "INVALID") << endl;
               
               
               Connection c;
               iph.GetDestIP(c.src);
               iph.GetSourceIP(c.dest);
               iph.GetProtocol(c.protocol);
               tcph.GetDestPort(c.srcport);
               tcph.GetSourcePort(c.destport);
               
               unsigned char flags;
               tcph.GetFlags(flags);
               
              
               unsigned int recSeqNum;
               tcph.GetSeqNum(recSeqNum);
               unsigned int ackNum = recSeqNum + 1;
               unsigned int ack;
               bool goodLastAcked = false;
               ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
               cs->state.SetLastRecvd(recSeqNum);
                if (IS_ACK(flags)) {
                   tcph.GetAckNum(ack);
                   goodLastAcked = cs->state.SetLastAcked(ack);
                   
               }
		 if (cs!=clist.end()){
                   if (!tcph.IsCorrectChecksum(receiveP)){
                       
                       cerr << "corrupt packet" << endl;
                       
                   } else {
                       cs->state.SetLastAcked(ackNum);
                       if (cs->state.GetState() != TIME_WAIT) {
                           cs->state.SetTimerTries(3);
                       }
                       cs->bTmrActive = true;
                       switch (cs->state.GetState()) {
                           case CLOSED:{
                               cerr << "CLOSED: ";
                           }
                               break;
			       // for server side
                           case LISTEN: {
                              ListenFunc(packetq, flags, c, currSeqNum, ackNum, mux, cs);

                           }
                               break;
                               
                           case SYN_RCVD:{
                              Syn_rcvdFunc(packetq, flags, c, currSeqNum, ackNum, mux, cs);
			            }
                               break;
			   case SYN_SENT:{
					 Syn_sentFunc(packetq, flags, c, currSeqNum, ackNum, mux, cs);
					 }
					 break;
                           case SYN_SENT1:{
                           
                               cerr << "SYN_SENT1: ";
                           }
                               break;
                           case  ESTABLISHED:{
                           
                               cerr << "ESTABLISHED: ";
                               if (IS_FIN(flags)) {
                                   
                                   cerr << "receive FIN, start to close" << endl;
                                   Packet np = SendAck(c, currSeqNum, ackNum, mux);
				   packetq.push_back(np);
                                   currSeqNum++;
                                   cs->state.SetState(CLOSE_WAIT);
                               }
                           }
                               break;
                               
                           case SEND_DATA:{
                           
                               cerr << "SEND_DATA: ";
                           }
                               break;
                           case CLOSE_WAIT:{
                           
                               cerr << "CLOSE_WAIT: ";
                               if (IS_FIN(flags)) {
                                   
                                   cerr << "receive FINACK, ready to close" << endl;
                                   Packet np = SendFin(c, currSeqNum, ackNum, mux);
                                   packetq.push_back(np);
                                   currSeqNum++;
                                   cs->state.SetState(LAST_ACK);
                                   cs->state.SetTimerTries(1);
                                   
                               }
                           }
                               break;
                               
                           case FIN_WAIT1: {
                               cerr << "FIN_WAIT1: ";
                               if (IS_FIN(flags) && !IS_ACK(flags)) {
                                   
                                   cerr << "receive FIN, ready to close" << endl;
                                   Packet np = SendAck(c, currSeqNum, ackNum, mux);
                                   packetq.push_back(np);
                                   cs->state.SetState(CLOSING);
                               } else if (IS_FIN(flags) && IS_ACK(flags)) {
                                   if (goodLastAcked) {
                                      
				       Packet np = SendAck(c, currSeqNum, ackNum,mux);	   
				       packetq.push_back(np);
                                       currSeqNum++;
                                       cs->state.SetState(TIME_WAIT);
                                       
                                   }
                                   
                               } else if (IS_ACK(flags) && goodLastAcked) {
                                   
                                   cerr << "receive ACK, enter FIN_WAIT2" << endl;
                                   cs->state.SetState(FIN_WAIT2);
                                   
                               }
                           }
                               break;
                           case FIN_WAIT2:{
                               
                               cerr << "FIN_WAIT2: ";
                               
                               if (IS_FIN(flags)) {
                                   
                                   cerr << "receive FIN, enter TIME_WAIT" << endl;
                                   Packet np = SendAck(c, currSeqNum, ackNum, mux);
                                   packetq.push_back(np);
                                   currSeqNum++;
                                   cs->state.SetState(TIME_WAIT);
                                   cs->state.SetTimerTries(2);
                               }
                               
                           }
                               break;
                           case CLOSING:{
                               
                               cerr << "CLOSING: ";
                               if (IS_ACK(flags) && goodLastAcked) {
                                   cerr << "receive ACK, enter TIME_WAIT" << endl;
                                   cs->state.SetState(TIME_WAIT);
                                   cs->state.SetTimerTries(2);
                                   
                               } else if (IS_FIN(flags)) {
                                   Packet np = SendAck(c, currSeqNum, ackNum, mux);
				   
                                   packetq.push_back(np);
                                   currSeqNum++;
                               }
                           }
                               break;
                           case LAST_ACK:{
                               cerr << "LAST_ACK: ";
                               if (IS_ACK(flags) && goodLastAcked) {
                                   cerr << "receive ACK, ready to close" << endl;
                                   cs->state.SetState(CLOSED);
                               }
                           }
                               break;
                               
                           case TIME_WAIT:{
                           
                               cerr << "TIME_WAIT: ";
                               
                               if(IS_FIN(flags) || IS_ACK(flags)){
                                   Packet np = SendAck(c, currSeqNum, ackNum, mux);
 				   packetq.push_back(np);
                                   currSeqNum++;
                               }
                           }
                               break;
                               
                           default:
                           	break;
                       }
                   }
               } else {
                   
                   cerr << "Could not find matching connection" << endl;
               }
           }
           
           //  Data from the Sockets layer above  //
           if (event.handle==sock) {
               SockRequestResponse req;
               unsigned int initialTimeout = 3,
               initialTimerTries = 3;
               MinetReceive(sock,req);
               cerr << "Received Socket Request:" << req << endl;
               
               switch (req.type) {
                   case CONNECT:
                   {
                      	   cerr << "CONNECT" << endl;
			   ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                       if (cs==clist.end()) {
                           cerr << "active open, send SYN " << endl;
                           TCPState tcps(currSeqNum, SYN_SENT, initialTimerTries);
                           tcps.SetLastRecvd(0);
                           tcps.SetLastSent(currSeqNum - 1);
                           tcps.SetLastAcked(currSeqNum - 1);
                           
                           ConnectionToStateMapping<TCPState> m(req.connection,
                                                                initialTimeout,
								tcps,
								true);
			
                           
                           clist.push_back(m);
                           unsigned char nflags;
                           SET_SYN(nflags);
                           Packet np = SendPacket( req.connection, nflags, currSeqNum, 0, mux);
                           packetq.push_back(np);
                           currSeqNum++;
                       }
                       
                       SockRequestResponse repl;
                       repl.type=STATUS;
                       repl.connection=req.connection;
                       repl.bytes=0;
                       repl.error=EOK;
                       MinetSend(sock,repl);
                   }
                       
                       break;
                       
                   case ACCEPT:{
                   
                       cerr <<"ACCEPT"<<endl;
                       cerr << "passive open, send SYNACK" << endl;
                       
                       TCPState tcps(currSeqNum, LISTEN, initialTimerTries);
                       
                       tcps.SetSendRwnd(3000);
                       tcps.SetLastRecvd(0);
                       tcps.SetLastSent(currSeqNum - 1);
                       tcps.SetLastAcked(currSeqNum - 1);
                       ConnectionToStateMapping<TCPState> m(req.connection,
                      						initialTimeout,
								tcps,
								false);
                       clist.push_back(m);
                       SockRequestResponse repl;
                       repl.type=STATUS;
                       repl.connection=req.connection;
                       repl.bytes=0;
                       repl.error=EOK;
                       MinetSend(sock,repl);
                       
                   }
                       
                       break;
                   case WRITE:{
                   
                       cerr << "WRITE" << endl;
                       ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                       SockRequestResponse repl;
                       repl.connection=req.connection;
                       repl.type=STATUS;
                       if (cs==clist.end()) {
                           
                           repl.error=ENOMATCH;
                           cout << clist << endl;
                       } else {
                           if (cs->state.GetState() == ESTABLISHED){
                           
                              // unsigned char nflags;
                              // SET_SYN(nflags);
                               
                              // Packet np = SendPacket(req.connection, nflags, currSeqNum, ackNum, mux);
                               
                                Packet np = SendSyn(req.connection, currSeqNum, 0, mux);
				packetq.push_back(np);
                               currSeqNum++;
                               cs->state.SetState(SYN_SENT);
                               
                           }
                           int bufsize = cs->state.SendBuffer.GetSize(),
                           acked = cs->state.GetLastAcked(),
                           sent = cs->state.GetLastSent();
                           unsigned size = bufsize - sent + acked;
                           if (size > 0) {
                               unsigned bytes = MIN_MACRO(IP_PACKET_MAX_LENGTH-TCP_HEADER_MAX_LENGTH, size);
                               
                               Packet np(req.data.ExtractFront(bytes));
                               
                               IPHeader sendIPHead;
                               sendIPHead.SetProtocol(IP_PROTO_TCP);
                               sendIPHead.SetSourceIP(req.connection.src);
                               sendIPHead.SetDestIP(req.connection.dest);
                               sendIPHead.SetTotalLength(bytes+TCP_HEADER_MAX_LENGTH+IP_HEADER_BASE_LENGTH);
                               
                               // push it onto the packet
                               
                               np.PushFrontHeader(sendIPHead);
                               // Now build the TCP header
                               TCPHeader sendTCPHead;
                               sendTCPHead.SetSourcePort(req.connection.srcport,np);
                               sendTCPHead.SetDestPort(req.connection.destport,np);
                               sendTCPHead.SetSeqNum(currSeqNum, np);
                               sendTCPHead.SetAckNum(0,np);
                               sendTCPHead.SetHeaderLen(TCP_HEADER_MAX_LENGTH,np);
                               
                               unsigned char nflags;
                               SET_SYN(nflags);
			       SET_PSH(nflags);
                               sendTCPHead.SetFlags(nflags,np);
                               sendTCPHead.SetWinSize(100,np);
                               
                               np.PushBackHeader(sendTCPHead);
                               MinetSend(mux,np);
                               
                           }
                           repl.bytes=req.data.GetSize();//bytes;
                           repl.error=EOK;
                       }
                       MinetSend(sock,repl);
                   }
                       break;
                   case FORWARD:{
                       
                   // ignored, send OK response
                       
                       cerr << "FORWARD" << endl;
                       SockRequestResponse repl;
                       repl.type=STATUS;
                       repl.connection=req.connection;
                       repl.bytes=0;
                       repl.error=EOK;
                       MinetSend(sock,repl);
                       
                   }
                       
                       break;
                   case CLOSE:{
                       
                   
                       cerr << "CLOSE" << endl;
                       ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                       SockRequestResponse repl;
                       repl.connection=req.connection;
                       repl.type=STATUS;
                       
                       if (cs==clist.end()) {
                           repl.error=ENOMATCH;
                           MinetSend(sock,repl);
                           
                       } else {
                           repl.error=EOK;
                           MinetSend(sock,repl);
                           switch (cs->state.GetState()) {
                                   
                               case LISTEN:
                               case SYN_SENT:
                               {
                                   clist.erase(cs);
                                   
                               }
                               case SYN_RCVD:
                               case ESTABLISHED:{
                               
                                   cerr << "start to CLOSE, send FIN" << endl;
                                //   unsigned char nflags;
                                 //  SET_FIN(nflags);
                                 //  Packet np = SendPacket( req.connection, nflags, currSeqNum, 0, mux);
                                   Packet np = SendFin(req.connection, currSeqNum, 0, mux);
 				   packetq.push_back(np);
                                   currSeqNum++;
                                   cs->state.SetState(FIN_WAIT1);
                               }
                                   break;
                                   
                               case CLOSE_WAIT:{
                               
                                   
                                   cerr << "ready to close, send FIN" << endl;
                                  // unsigned char nflags;
                                  // SET_FIN(nflags);
                                  // Packet np = SendPacket( req.connection, nflags, currSeqNum, 0, mux);
                                   
                                   Packet np = SendFin(req.connection, currSeqNum, 0, mux);

				   packetq.push_back(np);
                                   currSeqNum++;
                                   
                                   cs->state.SetState(LAST_ACK);
                                   
                               }
                                   break;
                               default:  break;
                           }
                       }
                   }
                       break;
                   case STATUS:
                       		break;
                       
                   default:{
                   
                       SockRequestResponse repl;
                       repl.type=STATUS;
                       repl.error=EWHAT;
                       MinetSend(sock,repl);
                   }
               }
           }
           cerr << "end main loop\n";
           
       }
       
   }
   return 0;
}
