/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

/**
 *
 * @author baskoro
 */
public class TransportLayerBufferHandler {
    private Map<Long, TcpBuffer> tcpBuffers;
    private ArrayList<TcpBuffer> readyTcpBuffers;
    private long timeout;
    private long lastPacketTimestamp;
    private boolean deleteReadConnection;
    private int lastReadIndex;
    private IpV4Handler ipV4Handler;
    
    public TransportLayerBufferHandler(long timeout, boolean deleteReadConnection, IpV4Handler ipv4Handler) {
        this.tcpBuffers = new HashMap<Long, TcpBuffer>();
        this.readyTcpBuffers = new ArrayList<TcpBuffer>();
        this.timeout = timeout;
        this.lastPacketTimestamp = Long.MAX_VALUE;
        this.deleteReadConnection = deleteReadConnection;
        this.lastReadIndex = 0;
        this.ipV4Handler = ipv4Handler;
    }
    
    public void processPacket(IpV4Packet ipv4Packet, Timestamp captureTimestamp) {
        this.lastPacketTimestamp = captureTimestamp.getTime();
        if(ipv4Packet.contains(TcpPacket.class)) {
            long[] hashes = TcpBuffer.calcHash(ipv4Packet);
            if(this.tcpBuffers.containsKey(hashes[0])) {
                this.tcpBuffers.get(hashes[0]).addSegment(ipv4Packet, captureTimestamp);
            }
            else if(this.tcpBuffers.containsKey(hashes[1])) {
                this.tcpBuffers.get(hashes[1]).addSegment(ipv4Packet, captureTimestamp);
            }
            else {
                TcpBuffer tcpBuffer = new TcpBuffer(ipv4Packet, this.timeout, this, captureTimestamp);
                tcpBuffer.start();
                this.tcpBuffers.put(tcpBuffer.getHashCode(), tcpBuffer);
            }
        }
        else if(ipv4Packet.contains(UdpPacket.class)) {

        }
    }
    
    public void moveReadyTcpConnection(long hashCode) {
        synchronized(this.tcpBuffers) {
            TcpBuffer tcpBuffer = this.tcpBuffers.remove(hashCode);
            this.readyTcpBuffers.add(tcpBuffer);
            //System.out.println("move: " + tcpBuffer.getTcpPayload(true));
        }
    }
    
    public void markAllConnectionReady() {
        for(TcpBuffer tcpBuffer : this.tcpBuffers.values()) {
            this.readyTcpBuffers.add(tcpBuffer);
        }
        
        this.tcpBuffers.clear();
    }

    public boolean isTimeout(long timestamp) {
        //System.err.println("Time: " + timestamp + " - " + this.lastPacketTimestamp + " = " + (this.lastPacketTimestamp - timestamp));
        return (this.lastPacketTimestamp - timestamp) > this.timeout;
    }
    
    public boolean hasReadyConnection() {
        if(this.isDeleteReadConnection()) {
            return this.readyTcpBuffers.size() > 0;
        }
        else {
            return (this.getLastReadIndex() < this.readyTcpBuffers.size()) && (this.readyTcpBuffers.size() > 0);
        }
    }
    
    public TcpBuffer popReadyConnection() {
        synchronized(this.readyTcpBuffers) {
            if(this.isDeleteReadConnection()) {
                TcpBuffer tcpBuffer = this.readyTcpBuffers.remove(0);
                return tcpBuffer;
            }
            else {
                System.out.println(this.getLastReadIndex());
                TcpBuffer tcpBuffer = this.readyTcpBuffers.get(this.getLastReadIndex());
                this.lastReadIndex++;
                return tcpBuffer;
            }
        }
    }
    
    /**
     * @return the deleteReadConnection
     */
    public boolean isDeleteReadConnection() {
        return deleteReadConnection;
    }
    
    public boolean isFinishedReading() {
        return this.ipV4Handler.isFinishedReading();
    }

    /**
     * @param deleteReadConnection the deleteReadConnection to set
     */
    public void setDeleteReadConnection(boolean deleteReadConnection) {
        this.deleteReadConnection = deleteReadConnection;
    }
    
    public void cleanupBuffers() {
        synchronized(this.tcpBuffers) {
            for(TcpBuffer tcpBuffer : this.tcpBuffers.values()) {
                tcpBuffer.setTcpState(TcpState.TIMEOUT);
            }
        }
    }
    
    public int getBufferSize() {
        return this.tcpBuffers.size();
    }
    
    public int getReadyBufferSize() {
        return this.readyTcpBuffers.size();
    }
    
    
    /**
     * @return the lastReadIndex
     */
    public int getLastReadIndex() {
        return lastReadIndex;
    }
    
    public void resetLastReadIndex() {
        this.lastReadIndex = 0;
    }
}
