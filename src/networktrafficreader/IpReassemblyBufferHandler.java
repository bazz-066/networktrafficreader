/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networktrafficreader;

/**
 *
 * @author baskoro
 */
public interface IpReassemblyBufferHandler {
    public void nextIpDatagram(FragmentedIpBuffer buffer);
}
