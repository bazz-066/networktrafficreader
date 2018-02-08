/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

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

/**
 *
 * @author baskoro
 */
public class TransportLayerBufferHandler implements IpReassemblyBufferHandler {
    private Map<Integer, TcpBuffer> tcpBuffers;
    private ArrayList<TcpBuffer> readyTcpBuffers;
    private Tcp tcp = new Tcp();
    private Udp udp = new Udp();
    private long timeout;
    private long lastPacketTimestamp;
    private boolean deleteReadConnection;
    private int lastReadIndex;
    
    public TransportLayerBufferHandler(long timeout, boolean deleteReadConnection) {
        this.tcpBuffers = new HashMap<Integer, TcpBuffer>();
        this.readyTcpBuffers = new ArrayList<TcpBuffer>();
        this.timeout = timeout;
        this.lastPacketTimestamp = Long.MAX_VALUE;
        this.deleteReadConnection = deleteReadConnection;
        this.lastReadIndex = -1;
    }
    
    @Override
    public void nextIpDatagram(JBuffer buffer) {
        if(buffer instanceof FragmentedIpBuffer) {
            FragmentedIpBuffer fragmentedIpBuffer = (FragmentedIpBuffer) buffer;
            if (fragmentedIpBuffer.isComplete() == false) {
                System.err.println("Warning: missing fragments");
            }
            else {
                try {
                    JPacket packet = new JMemoryPacket(JMemory.Type.POINTER);
                    packet.peer(fragmentedIpBuffer);
                    packet.getCaptureHeader().wirelen(fragmentedIpBuffer.size());
                    packet.getCaptureHeader().caplen(fragmentedIpBuffer.size());

                    packet.scan(Ip4.ID);

                    Ip4 ip = packet.getHeader(new Ip4());
                    ip.checksum(ip.calculateChecksum());

                    this.processPacket(packet);
                    this.lastPacketTimestamp = packet.getCaptureHeader().timestampInMillis();
                } catch (Exception ex) {
                    Logger.getLogger(TransportLayerBufferHandler.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        else {
            PcapPacket packet = null;
            try {
                packet = (PcapPacket) buffer;
                this.processPacket(packet);
                this.lastPacketTimestamp = packet.getCaptureHeader().timestampInMillis();
            } catch (Exception ex) {
                //System.err.println(packet.toString());
                Logger.getLogger(TransportLayerBufferHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public void processPacket(JPacket packet) throws Exception {
        if(packet.hasHeader(Tcp.ID)) {
            Tcp new_segment = packet.getHeader(new Tcp());
            if(this.tcpBuffers.containsKey(new_segment.hashCode())) {
                this.tcpBuffers.get(new_segment.hashCode()).addSegment(packet);
            }
            else {
                TcpBuffer tcpBuffer = new TcpBuffer(packet, this.timeout, this);
                tcpBuffer.start();
                this.tcpBuffers.put(tcpBuffer.hashCode(), tcpBuffer);
            }
        }
        else if(packet.hasHeader(new Udp())) {

        }
    }
    
    public void moveReadyTcpConnection(int hashCode) {
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
        return (timestamp - this.lastPacketTimestamp) > this.timeout;
    }
    
    public boolean hasReadyConnection() {
        if(this.isDeleteReadConnection()) {
            return this.readyTcpBuffers.size() > 0;
        }
        else {
            return (this.lastReadIndex < this.readyTcpBuffers.size()) && (this.readyTcpBuffers.size() > 0);
        }
    }
    
    public TcpBuffer popReadyConnection() {
        synchronized(this.readyTcpBuffers) {
            if(this.isDeleteReadConnection()) {
                TcpBuffer tcpBuffer = this.readyTcpBuffers.remove(0);
                return tcpBuffer;
            }
            else {
                TcpBuffer tcpBuffer = this.readyTcpBuffers.get(this.lastReadIndex);
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

    /**
     * @param deleteReadConnection the deleteReadConnection to set
     */
    public void setDeleteReadConnection(boolean deleteReadConnection) {
        this.deleteReadConnection = deleteReadConnection;
    }
}
