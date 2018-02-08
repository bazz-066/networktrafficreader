/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author baskoro
 */
public class IpReassembly implements PcapPacketHandler<Object>, Runnable {
    private static final int DEFAULT_REASSEMBLY_SIZE = 32 * 1024; // 8k
    private Ip4 ip4 = new Ip4();
    private Map<Integer, FragmentedIpBuffer> buffers = new HashMap<Integer, FragmentedIpBuffer>();
    private IpReassemblyBufferHandler handler;
    private final long timeout;
    private final Queue<FragmentedIpBuffer> timeoutQueue = new PriorityQueue<>();
    private boolean done;
                
    public IpReassembly(long timeout, IpReassemblyBufferHandler handler) {
        this.timeout = timeout;
        if(handler == null) {
            throw new NullPointerException();
        }
        this.handler = handler;
        this.done = false;
    }
    
    @Override
    public void nextPacket(PcapPacket packet, Object user) {
        if(packet.hasHeader(this.ip4)) {
            Ip4 ip4 = packet.getHeader(this.ip4);
            final int flags = ip4.flags();
            
            if((flags & Ip4.FLAG_MORE_FRAGMENTS) == 0 && ip4.offset() == 0) {
                this.dispatch(packet);
            }
            // Fragmented packet
            else if((flags & Ip4.FLAG_MORE_FRAGMENTS) != 0) {
                this.bufferFragment(packet, ip4);
            }
            // last packet or non-fragmented packet
            else {
                this.bufferLastFragment(packet, ip4);
            }
        }
    }
    
    private FragmentedIpBuffer getBuffer(Ip4 ip) {
        FragmentedIpBuffer buffer = this.buffers.get(ip.hashCode());
        if(buffer == null) {
            final long bufTimeout = System.currentTimeMillis() + this.timeout;
            buffer = new FragmentedIpBuffer(ip, DEFAULT_REASSEMBLY_SIZE, bufTimeout, ip.hashCode());
            this.buffers.put(ip.hashCode(), buffer);
        }
        
        return buffer;
    }
    
    private void dispatch(JBuffer buffer) {
        this.getHandler().nextIpDatagram(buffer);
    }
    
    private FragmentedIpBuffer bufferFragment(PcapPacket packet, Ip4 ip) {
        FragmentedIpBuffer buffer = this.getBuffer(ip);
        
        final int hlen = ip.hlen() * 4;
        final int len = ip.length() - hlen;
        final int packetOffset = ip.getOffset() + hlen;
        final int dgramOffset = ip.offset() * 8;
        
        buffer.addSegment(packet, dgramOffset, len, packetOffset);
        
        if(buffer.isComplete()) {
            if(this.buffers.remove(ip.hashCode()) == null) {
                System.err.println("bufferFragment(): failed to remove buffer");
                System.exit(0);
            }
            
            timeoutQueue.remove(buffer);
            this.dispatch(buffer);
        }
        
        return buffer;
    }
    
    private FragmentedIpBuffer bufferLastFragment(PcapPacket packet, Ip4 ip) {
        FragmentedIpBuffer buffer = this.getBuffer(ip);
        
        final int hlen = ip.hlen() * 4;
        final int len = ip.length() - hlen;
        final int packetOffset = ip.getOffset() + hlen;
        final int dgramOffset = ip.offset() * 8;
        
        buffer.addLastSegment(packet, dgramOffset, len, packetOffset);
        
        if(buffer.isComplete()) {
            if(this.buffers.remove(buffer.hashCode()) == null) {
                System.err.println("bufferLastFragment(): failed to remove buffer");
                System.exit(0);
            }
            
            timeoutQueue.remove(buffer);
            this.dispatch(buffer);
        }
        
        return buffer;
    }
    
    private void timeoutBuffers() {
        while(!this.timeoutQueue.isEmpty()) {
            if(this.timeoutQueue.peek().isTimedout()) {
                this.dispatch(timeoutQueue.poll());
            }
            else {
                break;
            }
        }
    }

    @Override
    public void run() {
        while(!this.isDone()) {
            this.timeoutBuffers();
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                Logger.getLogger(IpReassembly.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * @return the done
     */
    public boolean isDone() {
        return done;
    }
    
    /**
     * @param done the done to set
     */
    public void setDone(boolean done) {
        this.done = done;
        TransportLayerBufferHandler tlbh = (TransportLayerBufferHandler) this.handler;
        tlbh.markAllConnectionReady();
    }
    
    /**
     * @return the handler
     */
    public IpReassemblyBufferHandler getHandler() {
        return handler;
    }

    
}


