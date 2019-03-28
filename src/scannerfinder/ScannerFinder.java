package scannerfinder;

import com.sun.xml.internal.fastinfoset.util.StringArray;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
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

        pcap.loop(500000, new JPacketHandler<StringBuilder>() {
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
                    //System.out.println(counts.get(key)[2] + "   " + counts.get(key)[0]);
                }
            }

        }, errbuf);

        ArrayList<String> outputData = new ArrayList<>();
        for (JFlow flow : flows.values()) {
            //System.out.println(flow.getKey().toString());
            int[] tempCounts = counts.get(flow.getKey());
            //if zero SYNACKS and more than two SYNs
            if((tempCounts[2] == 0) && (tempCounts[0] > 2)){

            //  file add flow.toString();
            outputData.add(flow.toString()+'\n');
            //  file add "--> SYN Count:
            outputData.add("--> SYN Count: "+tempCounts[0]+'\n');
            //  file add "--> SYNACK Count:
            outputData.add("--> SYNACK Count: "+tempCounts[2]+'\n');
            //  file add "Port scanning possible."
            outputData.add("Port Scanning Possible"+'\n');
            }
            //If more than 0 SYN and SYNACKs
            else if((tempCounts[0] != 0) && (tempCounts[2] != 0)) {
                //If there is 3x or more SYNs than SYNACKS
                if((tempCounts[0] / tempCounts[2]) >= 3){
                    //  file add flow.toString();
                    outputData.add(flow.toString()+'\n');
                    //  file add "--> SYN Count:
                    outputData.add("--> SYN Count: "+tempCounts[0]+'\n');
                    //  file add "--> SYNACK Count:
                    outputData.add("--> SYNACK Count: "+tempCounts[2]+'\n');
                    //  file add "Port scanning possible."
                    outputData.add("Port Scanning Possible"+'\n');
                }
//                    System.out.println("------------");
//                    System.out.println(flow.toString());
//                    System.out.println("------------");
//                    System.out.println("SYN: " + tempCounts[0]);
//                    System.out.println("ACK: " + tempCounts[1]);
//                    System.out.println("SYNACK: " + tempCounts[2]);
//                    System.out.println("------------");

            }
        }
        //initialize file IO
        FileWriter fw;
        try{
            fw = new FileWriter("output.txt");
            for(int i = 0; i < outputData.size(); i++) {
                fw.write(outputData.get(i));
            }
            fw.close();
            System.out.println("Finished");

        } catch(IOException e){
            System.out.println("error writing file");
        }
    }
}
