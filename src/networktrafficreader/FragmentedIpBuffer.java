/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.Queue;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author baskoro
 */
public class FragmentedIpBuffer extends JBuffer implements Comparable<FragmentedIpBuffer> {

    private Ip4 header = new Ip4();
    private int ipDatagramLength = -1;
    private int bytesCopiedIntoBuffer = 20;
    
    private final int start = 20;
    private final long timeout;
    private final int hash;
    
    public FragmentedIpBuffer(Ip4 ip, int size, long timeout, int hash) {
        super(size);
        
        this.timeout = timeout;
        this.hash = hash;
        
        this.transferFrom(ip);
    }
    
    private void transferFrom(Ip4 ip) {
        //copy IP header as a template
        ip.transferTo(this, 0, 20, 0);
        
        this.header.peer(this, 0, 20);
        
        //reset some unnecessary stuff
        this.header.hlen(5);
        this.header.clearFlags(Ip4.FLAG_MORE_FRAGMENTS);
        this.header.offset(0);
        this.header.checksum(0);
    }
    
    public void addSegment(JBuffer packet, int offset, int length, int packetOffset) {
        this.bytesCopiedIntoBuffer += length;
        packet.transferTo(this, packetOffset, length, offset + this.start);
    }
    
    public void addLastSegment(JBuffer packet, int offset, int length, int packetOffset) {
        this.addSegment(packet, offset, length, packetOffset);
        this.ipDatagramLength = this.start + offset + length;
        
        super.setSize(this.ipDatagramLength);
        
        this.header.length(ipDatagramLength);
    }
    
    @Override
    public int hashCode() {
        return this.hash;
    }
    
    @Override
    public int compareTo(FragmentedIpBuffer o) {
        return (int) (o.timeout - this.timeout);
    }
    
    public boolean  isComplete() {
        return this.ipDatagramLength == this.bytesCopiedIntoBuffer;
    }
    
    public boolean isTimedout() {
        return this.timeout < System.currentTimeMillis();
    }
    
    public Ip4 getIpHeader() {
        return this.header;
    }
}
