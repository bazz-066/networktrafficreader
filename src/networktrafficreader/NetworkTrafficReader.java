/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 *
 * @author baskoro
 */
@SuppressWarnings("javadoc")
public class NetworkTrafficReader {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
//            StringBuilder errbuf = new StringBuilder();
//            Pcap pcap = Pcap.openOffline("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15-Source-Files/UNSW-NB15-pcap-files/pcaps-22-1-2015/attack/22-1-2017-Exploits.pcap", errbuf);
//            if(pcap == null) {
//                System.err.println(errbuf.toString());
//                return;
//            }
//            
//            NetworkTrafficReader.unbindProtocols();
//            
//            IpReassembly ipReassembly = new IpReassembly(5 * 1000, new TransportLayerBufferHandler(5000, true));
//            Thread t = new Thread(ipReassembly);
//            t.start();
//            
//            MessagePoper poper = new MessagePoper(ipReassembly);
//            poper.start();
//            
//            pcap.loop(-1, ipReassembly, null);
//            Thread.sleep(100);
//            ipReassembly.setDone(true);
//            t.join();
//            poper.join();
//            System.out.println("Done!");
            PcapHandle pcap = Pcaps.openOffline("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15-Source-Files/UNSW-NB15-pcap-files/pcaps-22-1-2015/normal/training-port-80.pcap");
            //PcapHandle pcap = Pcaps.openOffline("/home/baskoro/Documents/Doctoral/Research/neuralnetwork-java/libs/pcap4j/pcap4j-sample/src/main/resources/flagmentedEcho.pcap");
            IpV4Handler handler = new IpV4Handler(5000, true);
            MessagePoper poper = new MessagePoper(handler);
            poper.start();
            Packet packet;
            int counter = 0;
            while((packet = pcap.getNextPacket()) != null) {
                handler.processPacket(packet, pcap.getTimestamp());
                
                counter++;
            }
            handler.setDone(true);
            handler.getTransportLayerHandler().cleanupBuffers();
            Thread.sleep(100);
            
            //packet.get(TcpPacket.TcpHeader);
            System.out.println("counter: " + counter);
        } catch (PcapNativeException ex) {
            Logger.getLogger(NetworkTrafficReader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NotOpenException ex) {
            Logger.getLogger(NetworkTrafficReader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedException ex) {
            Logger.getLogger(NetworkTrafficReader.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
}
