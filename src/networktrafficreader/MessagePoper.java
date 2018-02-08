/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author baskoro
 */
public class MessagePoper extends Thread {
    private IpReassembly ipReassembly;

    public MessagePoper(IpReassembly ipReassembly) {
        this.ipReassembly = ipReassembly;
    }

    public void run() {
        long counter = 0;
        TransportLayerBufferHandler tblh = (TransportLayerBufferHandler) this.ipReassembly.getHandler();
        while(!this.ipReassembly.isDone() || tblh.hasReadyConnection()) {
            if(tblh.hasReadyConnection()) {
                TcpBuffer tcpBuffer = tblh.popReadyConnection();
                counter++;
                //System.out.println("Num of connections: " + counter);
                //System.out.println("payload: " + tcpBuffer.getTcpPayload(true));
                //System.out.println("payload: " + tcpBuffer.getTcpPayload(false));
                //System.out.println("num of packets to server: " + tcpBuffer.getNumberOfPackets(true));
                //System.out.println("num of packets to client: " + tcpBuffer.getNumberOfPackets(false));
            }
            else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                    Logger.getLogger(MessagePoper.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        
        System.out.println("Num of connections: " + counter);
    }
}
