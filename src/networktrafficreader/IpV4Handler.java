/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.IpV4Helper;

/**
 *
 * @author baskoro
 */
public class IpV4Handler implements Runnable {
    private HashMap<Short, List<IpV4Packet>> ipv4Packets;
    private HashMap<Short, List<Packet>> originalPackets;
    private long timeout;
    private TransportLayerBufferHandler transportLayerHandler;
    private boolean done;
    
    public IpV4Handler(long timeout) {
        this.timeout = timeout;
        this.ipv4Packets = new HashMap<Short, List<IpV4Packet>>();
        this.originalPackets = new HashMap<Short, List<Packet>>();
        this.transportLayerHandler = new TransportLayerBufferHandler(this.timeout, true, this);
        this.done = false;
    }

    public List<IpV4Packet> getBuffer(short id) {
        // The previous packet is already in the buffer
        if(this.ipv4Packets.containsKey(id)) {
            return this.ipv4Packets.get(id);
        }
        else {
            List<IpV4Packet> buffer = new ArrayList<>();
            this.ipv4Packets.put(id, buffer);
            return buffer;
        }
    }
    
    public void processPacket(Packet packet, Timestamp timestamp) {
        IpV4Packet ipv4Packet = (IpV4Packet) packet.getPayload();
        IpV4Packet.IpV4Header ipv4Header = ipv4Packet.getHeader();
        
        if(!ipv4Header.getMoreFragmentFlag() && ipv4Header.getFragmentOffset() == 0) { // non-fragmented packets
            //System.out.println(packet);
            if(ipv4Packet.contains(TcpPacket.class)) {
                long[] hashes = TcpBuffer.calcHash(ipv4Packet);
                this.getTransportLayerHandler().processPacket(ipv4Packet, timestamp);
            }
        }
        else if(ipv4Header.getMoreFragmentFlag()) { // fragmented packets
            List<IpV4Packet> buffer = this.getBuffer(ipv4Header.getIdentification());
            buffer.add(ipv4Packet);
        }
        else { // end of fragmented packets
            List<IpV4Packet> buffer = this.getBuffer(ipv4Header.getIdentification());
            buffer.add(ipv4Packet);
            this.ipv4Packets.remove(ipv4Header.getIdentification());
            try {
                IpV4Packet defragmentedPacket = IpV4Helper.defragment(buffer);
                if(defragmentedPacket.contains(TcpPacket.class)) {
                    long[] hashes = TcpBuffer.calcHash(defragmentedPacket);
                    this.getTransportLayerHandler().processPacket(ipv4Packet, timestamp);
                }
            }
            catch(IllegalArgumentException e) {
                System.err.println(e.getMessage());
            }
            //System.out.println(defragmentedPacket);
        }
    }
    
    /**
     * @return the transportLayerHandler
     */
    public TransportLayerBufferHandler getTransportLayerHandler() {
        return transportLayerHandler;
    }
    
    @Override
    public void run() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * @return the done
     */
    public boolean isDone() {
        if(!this.done) {
            return false;
        }
        else if(this.transportLayerHandler.getBufferSize() <= 0 && this.transportLayerHandler.getReadyBufferSize() <= 0) {
            return true;
        }
        else {
            return false;
        }
    }
    
    public boolean isFinishedReading() {
        return this.done;
    }

    /**
     * @param done the done to set
     */
    public void setDone(boolean done) {
        this.done = done;
    }
}
