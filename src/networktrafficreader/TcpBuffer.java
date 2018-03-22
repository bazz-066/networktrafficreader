/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.net.Inet4Address;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 *
 * @author baskoro
 */
public class TcpBuffer extends Thread {

    /**
     * @return the tcpState
     */
    public TcpState getTcpState() {
        return tcpState;
    }
    private long timeout;
    private long hashCode;
    private int source;
    private ArrayList<TcpPacket> serverBuffer, clientBuffer;
    private TcpState tcpState;
    private long lastClientSeq, lastClientAck, lastServerSeq, lastServerAck;
    private long actualStartTimestamp, actualStopTimestamp; // timestamp obtained from the packet header
    private long startTimeStamp, stopTimestamp; // timestamp obtained from the system time
    private TransportLayerBufferHandler bufferHandler;
    private Inet4Address srcAddress, dstAddress;
    private int srcPort, dstPort;
    
    public TcpBuffer(IpV4Packet ipv4Packet, long timeout, TransportLayerBufferHandler bufferHandler, Timestamp captureTimestamp) {
        this.timeout = timeout;
        IpV4Packet.IpV4Header ipv4Header = ipv4Packet.getHeader();
        TcpPacket tcpPacket = (TcpPacket) ipv4Packet.getPayload();
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        long[] hashes  = TcpBuffer.calcHash(ipv4Packet);
        
        // It should be impossible for an initial TCP segment to have SYN and ACK.
        // The word behind buffer is meant to be the destination
        if(tcpHeader.getSyn() && tcpHeader.getAck()) {
            this.source = tcpHeader.getDstPort().valueAsInt();
            this.tcpState = TcpState.SYN_RCVD;
            this.clientBuffer = new ArrayList<>();
            this.serverBuffer = new ArrayList<>();
            this.clientBuffer.add(tcpPacket);
            
            this.lastClientAck = -1;
            this.lastClientSeq = -1;
            this.lastServerAck = -1;
            this.lastServerSeq = -1;
            this.actualStartTimestamp = captureTimestamp.getTime();
            this.startTimeStamp = System.currentTimeMillis();
            this.actualStopTimestamp = captureTimestamp.getTime();
            this.stopTimestamp = System.currentTimeMillis();
            this.bufferHandler = bufferHandler;
            this.hashCode = hashes[1];
            
            this.srcAddress = ipv4Header.getDstAddr();
            this.dstAddress = ipv4Header.getSrcAddr();
            this.srcPort = tcpHeader.getDstPort().valueAsInt();
            this.dstPort = tcpHeader.getSrcPort().valueAsInt();
        }
        else {
            //if(tcp.flags_SYN() && !tcp.flags_ACK()) {
            this.source = tcpHeader.getSrcPort().valueAsInt();
            this.tcpState = TcpState.SYN_SENT;
            this.clientBuffer = new ArrayList<>();
            this.serverBuffer = new ArrayList<>();
            this.serverBuffer.add(tcpPacket);
            
            this.lastClientAck = -1;
            this.lastClientSeq = -1;
            this.lastServerAck = -1;
            this.lastServerSeq = -1;
            this.actualStartTimestamp = captureTimestamp.getTime();
            this.startTimeStamp = System.currentTimeMillis();
            this.actualStopTimestamp = captureTimestamp.getTime();
            this.stopTimestamp = System.currentTimeMillis();
            this.bufferHandler = bufferHandler;
            this.hashCode = hashes[0];
            
            this.srcAddress = ipv4Header.getSrcAddr();
            this.dstAddress = ipv4Header.getDstAddr();
            this.srcPort = tcpHeader.getSrcPort().valueAsInt();
            this.dstPort = tcpHeader.getDstPort().valueAsInt();
        }
        //else {
        //    System.err.println("a TCP connection started without SYN/SYN-ACK packet\n");
        //}
    }
    
    public void run() {
        while(true) {
            if(this.bufferHandler.isTimeout(this.actualStopTimestamp)) {
                break;
            }
            else if(this.getTcpState() == TcpState.TIME_WAIT) {
                break;
            }
            else if(this.bufferHandler.isFinishedReading()) {
                break;
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
    
    public void addSegment(IpV4Packet ipv4Packet, Timestamp captureTimestamp) {
        TcpPacket newSegment = (TcpPacket) ipv4Packet.getPayload();
        TcpPacket.TcpHeader tcpHeader = newSegment.getHeader();
        long actualTimestamp = captureTimestamp.getTime();
        
        switch(this.getTcpState()) {
            case SYN_SENT:
                if(tcpHeader.getSyn() && tcpHeader.getAck()) {
                    this.setTcpState(TcpState.SYN_RCVD);
                    this.clientBuffer.add(newSegment);
                    this.actualStopTimestamp = actualTimestamp;
                }
                break;
            case SYN_RCVD:
                if(tcpHeader.getAck()) {
                    this.setTcpState(TcpState.ESTABLISHED);
                    this.serverBuffer.add(newSegment);
                    this.actualStopTimestamp = actualTimestamp;
                }
                break;
            case ESTABLISHED:
                if(tcpHeader.getFin()) {
                    this.setTcpState(TcpState.FIN_WAIT_1);
                }
                this.insertSegment(newSegment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case FIN_WAIT_1:
                if(tcpHeader.getFin()) {
                    this.setTcpState(TcpState.FIN_WAIT_2);
                }
                this.insertSegment(newSegment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case FIN_WAIT_2:
                if(tcpHeader.getFin()) {
                    this.setTcpState(TcpState.TIME_WAIT);
                }
                this.insertSegment(newSegment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
            case TIME_WAIT:
                this.insertSegment(newSegment);
                this.actualStopTimestamp = actualTimestamp;
                this.stopTimestamp = System.currentTimeMillis();
                break;
        }
        
    }
    
    public long getHashCode() {
        return this.hashCode;
    }
    
    public String getTcpPayload(boolean toServer) {
        StringBuffer buffer = new StringBuffer();
        if(toServer) {
            for(TcpPacket segment : this.serverBuffer) {
                Packet payload = segment.getPayload();
                if(payload != null) {
                    buffer.append(new String(payload.getRawData()));
                } 
            }
        }
        else {
            for(TcpPacket segment : this.clientBuffer) {
                Packet payload = segment.getPayload();
                if(payload != null) {
                    buffer.append(new String(payload.getRawData()));
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
    
    private void insertSegment(TcpPacket newSegment) {
        TcpPacket.TcpHeader newTcpHeader = newSegment.getHeader();
        if(newTcpHeader.getSrcPort().valueAsInt() == this.source) { // to server
            if(newTcpHeader.getSequenceNumber() > this.lastServerSeq) { // an in-order packet
                this.serverBuffer.add(newSegment);
                this.lastServerSeq = newTcpHeader.getSequenceNumber();
                this.lastServerAck = newTcpHeader.getAcknowledgmentNumber();
            }
            else {
                for(int i=this.serverBuffer.size()-1; i>=0; i--) {
                    TcpPacket segment = this.serverBuffer.get(i);
                    TcpPacket.TcpHeader header = segment.getHeader();
                    int newSegmentPayloadLength = newSegment.getPayload() == null ? 0 : newSegment.getPayload().length();
                    int oldSegmentPayloadLength = segment.getPayload() == null ? 0 : segment.getPayload().length();
                    if(header.getSequenceNumber() == newTcpHeader.getSequenceNumber() && oldSegmentPayloadLength == newSegmentPayloadLength) { //retransmitted packet
                        break;
                    }
                    else if(header.getSequenceNumber() == newTcpHeader.getSequenceNumber() && oldSegmentPayloadLength == newSegmentPayloadLength) {
                        this.serverBuffer.add(i+1, newSegment); 
                        break;
                    }
                    else if(header.getSequenceNumber() < newTcpHeader.getSequenceNumber()) {
                        this.serverBuffer.add(i+1, newSegment);
                        break;
                    }
                }
            }
        }
        else { // to client
            if(newTcpHeader.getSequenceNumber() > this.lastClientSeq) { // an in-order packet
                this.clientBuffer.add(newSegment);
                this.lastClientSeq = newTcpHeader.getSequenceNumber();
                this.lastClientAck = newTcpHeader.getAcknowledgmentNumber();
            }
            else {
                for(int i=this.clientBuffer.size()-1; i>=0; i--) {
                    TcpPacket segment = this.clientBuffer.get(i);
                    TcpPacket.TcpHeader header = segment.getHeader();
                    int newSegmentPayloadLength = newSegment.getPayload() == null ? 0 : newSegment.getPayload().length();
                    int oldSegmentPayloadLength = segment.getPayload() == null ? 0 : segment.getPayload().length();
                    if(header.getSequenceNumber() == newTcpHeader.getSequenceNumber() && oldSegmentPayloadLength == newSegmentPayloadLength) { //retransmitted packet
                        break;
                    }
                    else if(header.getSequenceNumber() == newTcpHeader.getSequenceNumber() && oldSegmentPayloadLength == newSegmentPayloadLength) {
                        this.clientBuffer.add(i+1, newSegment);
                        break;
                    }
                    else if(header.getSequenceNumber() < newTcpHeader.getSequenceNumber()) {
                        this.clientBuffer.add(i+1, newSegment);
                        break;
                    }
                }
            }
        }
    }
    
    public String getTcpTuple() {
        return this.srcAddress.getHostAddress() + "," + this.srcPort + "," + this.dstAddress.getHostAddress() + "," + this.dstPort;
    }
    
    /**
     * @param tcpState the tcpState to set
     */
    public void setTcpState(TcpState tcpState) {
        this.tcpState = tcpState;
    }
    
    public static long[] calcHash(IpV4Packet ipv4Packet) {
        long[] hashes = new long[2];
        IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();
        TcpPacket tcpPacket = (TcpPacket) ipv4Packet.getPayload();
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        String forwardPair = ipHeader.getSrcAddr().toString() + "|" + tcpHeader.getSrcPort().valueAsString() + "|" + ipHeader.getDstAddr().toString() + "|" + tcpHeader.getDstPort().valueAsString();
        String reversePair = ipHeader.getDstAddr().toString() + "|" + tcpHeader.getDstPort().valueAsString() + "|" + ipHeader.getSrcAddr().toString() + "|" + tcpHeader.getSrcPort().valueAsString();

        CRC32 digest = new CRC32();
        digest.update(forwardPair.getBytes());
        hashes[0] = digest.getValue();

        digest = new CRC32();
        digest.update(reversePair.getBytes());
        hashes[1] = digest.getValue();
        return hashes;
    }
}
