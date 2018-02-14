/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import org.pcap4j.core.PcapHandle;

/**
 *
 * @author baskoro
 */
public abstract class PcapReaderInterface extends Thread {
    protected PcapHandle pcapHandle;
    protected IpV4Handler ipv4Handler;
    protected TransportLayerBufferHandler transportLayerHandler;
    protected long counter = 0;
    
    /**
     * @return the ipv4Handler
     */
    public IpV4Handler getIpv4Handler() {
        return ipv4Handler;
    }
    
    /**
     * @return the transportLayerHandler
     */
    public TransportLayerBufferHandler getTransportLayerHandler() {
        return transportLayerHandler;
    }
}
