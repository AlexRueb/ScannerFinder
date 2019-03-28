package scannerfinder;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScannerFinder {
    public static void main(String[] args){
        final String FILENAME = "input/input.pcap";
        final StringBuilder errbuf = new StringBuilder();
        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);

        if(pcap == null){
            System.err.println(errbuf);
        }

        JScanner.getThreadLocal().setFrameNumber(0);

        final PcapPacket packet = new PcapPacket(JMemory.POINTER);
        final Tcp tcp = new Tcp();
        final Map<JFlowKey, JFlow> flows = new HashMap<JFlowKey, JFlow>();

        // int[0] is SYN only, int[1] is ACK only, and int[2] is SYNACK
        final Map<JFlowKey, int[]> counts = new HashMap<JFlowKey, int[]>();

        pcap.loop(150000, new JPacketHandler<StringBuilder>() {
            final Tcp tcp = new Tcp();
            final Http http = new Http();
            public void nextPacket(JPacket packet, StringBuilder errbuf) {

                // Get flow key of current packet
                final JFlowKey key = packet.getState().getFlowKey();

                //Test if current flow exists in our HashMap
                JFlow flow = flows.get(key);
                if(flow == null){
                    // Add to HashMap if flow not already in it
                    flows.put(key, flow = new JFlow(key));
                    counts.put(key, new int[3]);
                }

//                System.out.println(packet);

                if (packet.hasHeader(Tcp.ID)) {
                    packet.getHeader(tcp);
                }

                if (packet.hasHeader(tcp)) {
                    flow.add(new PcapPacket(packet));
                    if (packet.getHeader(tcp).flags_ACK() && packet.getHeader(tcp).flags_SYN() ){
                        //System.out.println("Has     BOTH");
                        counts.get(key)[2]++;
                    }
                    else if (packet.getHeader(tcp).flags_SYN() && !packet.getHeader(tcp).flags_ACK()){
                        //System.out.println("has                    SYN");
                        counts.get(key)[0]++;
                    }
                    else if (packet.getHeader(tcp).flags_ACK()){
                        //System.out.println("has ACK");
                        counts.get(key)[1]++;
                    }
                }
                if(counts.get(key)[2] != counts.get(key)[0]) {
                    System.out.println(counts.get(key)[2] + "   " + counts.get(key)[0]);
                }
            }

        }, errbuf);

        for (JFlow flow : flows.values()) {
            //System.out.println(flow.getKey().toString());
            int[] tempCounts = counts.get(flow.getKey());
            if(tempCounts[0] != 0 || tempCounts[2] != 0) {
                if(tempCounts[0] / tempCounts[2] > 3){
                    System.out.println("------------");
                    System.out.println(flow.toString());
                    System.out.println("------------");
                    System.out.println("SYN: " + tempCounts[0]);
                    //System.out.println("ACK: " + tempCounts[1]);
                    System.out.println("SYNACK: " + tempCounts[2]);
                    System.out.println("------------");
                }
            }
        }
    }
}
