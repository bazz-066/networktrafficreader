/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author baskoro
 */
public class NetworkTrafficReader {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline("/media/baskoro/HD-LXU3/Datasets/UNSW/UNSW-NB15-Source-Files/UNSW-NB15-pcap-files/pcaps-22-1-2015/normal/training-port-80.pcap", errbuf);
        if(pcap == null) {
            System.err.println(errbuf.toString());
            return;
        }
        
        IpReassembly ipReassembly = new IpReassembly(5 * 1000, new IpReassemblyBufferHandler() {
            @Override
            public void nextIpDatagram(FragmentedIpBuffer buffer) {
                if (buffer.isComplete() == false) {
                    System.err.println("Warning: missing fragments");
                }
                else {
                    JPacket packet = new JMemoryPacket(JMemory.Type.POINTER);
                    packet.peer(buffer);
                    packet.getCaptureHeader().wirelen(buffer.size());
                    packet.getCaptureHeader().caplen(buffer.size());
                    
                    packet.scan(Ip4.ID);
                    
                    Ip4 ip = packet.getHeader(new Ip4());
                    ip.checksum(ip.calculateChecksum());
                    
                    System.out.println(packet.toString());
                }
            }
        });
        
        pcap.loop(100, ipReassembly, null);
        System.out.println("Done!");
        ipReassembly.setDone(true);
    }
    
}
