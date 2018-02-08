/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author baskoro
 */
public class TcpBuffer extends Thread {
    private long timeout;
    private int hashCode;
    private int source;
    private ArrayList<Tcp> serverBuffer, clientBuffer;
    private TcpState state;
    private long lastClientSeq, lastClientAck, lastServerSeq, lastServerAck;
    private long actualStartTimestamp, actualStopTimestamp; // timestamp obtained from the packet header
    private long startTimeStamp, stopTimestamp; // timestamp obtained from the system time
    private TransportLayerBufferHandler bufferHandler;
    
    public TcpBuffer(JPacket packet, long timeout, TransportLayerBufferHandler bufferHandler) throws Exception {
        this.timeout = timeout;
        Tcp tcp;
        tcp = packet.getHeader(new Tcp());
        this.hashCode = tcp.hashCode();
        
        // It should be impossible for an initial TCP segment to have SYN and ACK.
        // The word behind buffer is meant to be the destination
        if(tcp.flags_SYN() && tcp.flags_ACK()) {
            this.source = tcp.destination();
            this.state = TcpState.SYN_RCVD;
            this.clientBuffer = new ArrayList<>();
            this.serverBuffer = new ArrayList<>();
            this.clientBuffer.add(tcp);
            
            this.lastClientAck = -1;
            this.lastClientSeq = -1;
            this.lastServerAck = -1;
            this.lastServerSeq = -1;
            this.actualStartTimestamp = packet.getCaptureHeader().timestampInMillis();
            this.startTimeStamp = System.currentTimeMillis();
            this.actualStopTimestamp = packet.getCaptureHeader().timestampInMillis();
            this.stopTimestamp = System.currentTimeMillis();
            this.bufferHandler = bufferHandler;
        }
        else {
            //if(tcp.flags_SYN() && !tcp.flags_ACK()) {
            this.source = tcp.source();
            this.state = TcpState.SYN_SENT;
            this.clientBuffer = new ArrayList<>();
            this.serverBuffer = new ArrayList<>();
            this.serverBuffer.add(tcp);
            
            this.lastClientAck = -1;
            this.lastClientSeq = -1;
            this.lastServerAck = -1;
            this.lastServerSeq = -1;
            this.actualStartTimestamp = packet.getCaptureHeader().timestampInMillis();
            this.startTimeStamp = System.currentTimeMillis();
            this.actualStopTimestamp = packet.getCaptureHeader().timestampInMillis();
            this.stopTimestamp = System.currentTimeMillis();
            this.bufferHandler = bufferHandler;
        }
        //else {
        //    System.err.println("a TCP connection started without SYN/SYN-ACK packet\n");
        //}
    }
    
    public void run() {
        while(this.state != TcpState.TIME_WAIT && this.state != TcpState.TIMEOUT) {
            if(this.bufferHandler.isTimeout(this.actualStopTimestamp)) {
                this.state = TcpState.TIMEOUT;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                Logger.getLogger(TcpBuffer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        this.stopTimestamp = System.currentTimeMillis();
        this.bufferHandler.moveReadyTcpConnection(this.hashCode);
    }
    
    public void addSegment(JPacket packet) {
        Tcp new_segment = packet.getHeader(new Tcp());
        long actualTimestamp = packet.getCaptureHeader().timestampInMillis();
        //System.err.println("+ " + new String(new_segment.getPayload()));
        
        switch(this.state) {
            case SYN_SENT:
                if(new_segment.flags_SYN() && new_segment.flags_ACK()) {
                    this.state = TcpState.SYN_RCVD;
                    this.clientBuffer.add(new_segment);
                    this.actualStopTimestamp = actualTimestamp;
                }
                break;
            case SYN_RCVD:
                if(new_segment.flags_ACK()) {
                    this.state = TcpState.ESTABLISHED;
                    this.serverBuffer.add(new_segment);
                    this.actualStopTimestamp = actualTimestamp;
                }
                break;
            case ESTABLISHED:
                if(new_segment.flags_FIN()) {
                    this.state = TcpState.FIN_WAIT_1;
                }
                this.insertSegment(new_segment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case FIN_WAIT_1:
                if(new_segment.flags_FIN()) {
                    this.state = TcpState.FIN_WAIT_2;
                }
                this.insertSegment(new_segment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case FIN_WAIT_2:
                if(new_segment.flags_FIN()) {
                    this.state = TcpState.TIME_WAIT;
                }
                this.insertSegment(new_segment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case TIME_WAIT:
                this.insertSegment(new_segment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
        }
        
    }
    
    public int hashCode() {
        return this.hashCode;
    }
    
    public String getTcpPayload(boolean toServer) {
        StringBuffer buffer = new StringBuffer();
        if(toServer) {
            for(Tcp segment : this.serverBuffer) {
                if(segment.getPayloadLength() > 0) {
                    buffer.append(new String(segment.getPayload()));
                } 
            }
        }
        else {
            for(Tcp segment : this.clientBuffer) {
                if(segment.getPayloadLength() > 0) {
                    buffer.append(new String(segment.getPayload()));
                } 
            }
        }
        
        return buffer.toString();
    } 
    
    public int getNumberOfPackets(boolean toServer) {
        if(toServer) {
            return this.serverBuffer.size();
        }
        else {
            return this.clientBuffer.size();
        }
    }
    
    private void insertSegment(Tcp new_segment) {
        if(new_segment.source() == this.source) { // to server
            if(new_segment.seq() > this.lastServerSeq) { // an in-order packet
                this.serverBuffer.add(new_segment);
                this.lastServerSeq = new_segment.seq();
                this.lastServerAck = new_segment.ack();
            }
            else {
                for(int i=this.serverBuffer.size()-1; i>=0; i--) {
                    Tcp segment = this.serverBuffer.get(i);
                    int x = segment.getPayloadLength();
                    int y = new_segment.getPayloadLength();
                    if(segment.seq() == new_segment.seq() && segment.getPayloadLength() == new_segment.getPayloadLength()) { //retransmitted packet
                        break;
                    }
                    else if(segment.seq() == new_segment.seq() && segment.getPayloadLength() != new_segment.getPayloadLength()) {
                        this.serverBuffer.add(i+1, new_segment);
                        break;
                    }
                    else if(segment.seq() < new_segment.seq()) {
                        this.serverBuffer.add(i+1, new_segment);
                        break;
                    }
                }
            }
        }
        else { // to client
            if(new_segment.seq() > this.lastClientSeq) { // an in-order packet
                this.clientBuffer.add(new_segment);
                this.lastClientSeq = new_segment.seq();
                this.lastClientAck = new_segment.ack();
            }
            else {
                for(int i=this.clientBuffer.size()-1; i>=0; i--) {
                    Tcp segment = this.clientBuffer.get(i);
                    if(segment.seq() == new_segment.seq() && segment.getPayloadLength() == new_segment.getPayloadLength()) { //retransmitted packet
                        break;
                    }
                    else if(segment.seq() == new_segment.seq() && segment.getPayloadLength() != new_segment.getPayloadLength()) {
                        this.clientBuffer.add(i+1, new_segment);
                        break;
                    }
                    else if(segment.seq() < new_segment.seq()) {
                        this.clientBuffer.add(i+1, new_segment);
                        break;
                    }
                }
            }
        }
    }
}
