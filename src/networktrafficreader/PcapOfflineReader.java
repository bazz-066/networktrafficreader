/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

/**
 *
 * @author baskoro
 */
public class PcapOfflineReader extends PcapReaderInterface {
    private String pcapFilename;
    
    public PcapOfflineReader(String pcapFilename, long timeout) throws PcapNativeException {
        this.pcapFilename = pcapFilename;
        this.pcapHandle = Pcaps.openOffline(this.pcapFilename);
        this.ipv4Handler = new IpV4Handler(timeout);
        this.transportLayerHandler = this.ipv4Handler.getTransportLayerHandler();
    }
    
    public void run() {
        try {
            Packet packet;
            
            while((packet = this.pcapHandle.getNextPacket()) != null) {
                this.ipv4Handler.processPacket(packet, this.pcapHandle.getTimestamp());
                
                this.counter++;
            }
            this.getTransportLayerHandler().cleanupBuffers();
            Thread.sleep(100);
            this.ipv4Handler.setDone(true);
        } 
        catch (NotOpenException ex) {
            Logger.getLogger(PcapOfflineReader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(PcapOfflineReader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}