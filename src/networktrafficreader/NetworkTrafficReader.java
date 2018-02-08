/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.protocol.JProtocol;
import static org.jnetpcap.protocol.JProtocol.SLL;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.voip.Sip;

/**
 *
 * @author baskoro
 */
public class NetworkTrafficReader {

    public static void unbindProtocols() {
        JRegistry.resetBindings(SLL.getId());
        JRegistry.resetBindings(Http.ID);
        JRegistry.resetBindings(Sip.ID);
        JPacket.getDefaultScanner().reloadAll();
    }    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            StringBuilder errbuf = new StringBuilder();
            Pcap pcap = Pcap.openOffline("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15-Source-Files/UNSW-NB15-pcap-files/pcaps-22-1-2015/attack/22-1-2017-Exploits.pcap", errbuf);
            if(pcap == null) {
                System.err.println(errbuf.toString());
                return;
            }
            
            NetworkTrafficReader.unbindProtocols();
            
            IpReassembly ipReassembly = new IpReassembly(5 * 1000, new TransportLayerBufferHandler(5000, true));
            Thread t = new Thread(ipReassembly);
            t.start();
            
            MessagePoper poper = new MessagePoper(ipReassembly);
            poper.start();
            
            pcap.loop(-1, ipReassembly, null);
            Thread.sleep(100);
            ipReassembly.setDone(true);
            t.join();
            poper.join();
            System.out.println("Done!");
        } catch (InterruptedException ex) {
            Logger.getLogger(NetworkTrafficReader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
