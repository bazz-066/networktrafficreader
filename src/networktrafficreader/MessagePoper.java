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
    private IpV4Handler ipv4Handler;

    public MessagePoper(IpV4Handler ipv4Handler) {
        this.ipv4Handler = ipv4Handler;
    }

    public void run() {
        long counter = 0;
        TransportLayerBufferHandler tblh = (TransportLayerBufferHandler) this.ipv4Handler.getTransportLayerHandler();
        while(!this.ipv4Handler.isDone()) {
            if(tblh.hasReadyConnection()) {
                TcpBuffer tcpBuffer = tblh.popReadyConnection();
                counter++;
                if(tcpBuffer == null) {
                    System.out.println("NULL," + counter);
                }
                else {
                    System.out.println("Connection: " + counter);
                    //System.out.println(tcpBuffer.getTcpTuple());
                }
                //System.out.println("Num of connections: " + counter);
                //System.out.println("payload: " + tcpBuffer.getTcpPayload(true));
                //System.out.println("payload: " + tcpBuffer.getTcpPayload(false));
                //System.out.println("num of packets to server: " + tcpBuffer.getNumberOfPackets(true));
                //System.out.println("num of packets to client: " + tcpBuffer.getNumberOfPackets(false));
            }
            else {
                try {
                    Thread.sleep(100);
                    System.out.println("sleep");
                } catch (InterruptedException ex) {
                    Logger.getLogger(MessagePoper.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        
        System.out.println("Poper Finished. Num of connections: " + counter);
    }
}
