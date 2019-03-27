package scannerfinder;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JFlowMap;

public class ScannerFinder {
    public static void main(String[] args){
        // TODO code application logic here
        final String FILENAME = "input/input.pcap";
        final StringBuilder errbuf = new StringBuilder();
        final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
        if(pcap == null){
            System.err.println(errbuf);
        }

        JFlowMap superFlowMap = new JFlowMap();
        pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);

        System.out.printf("superFlowMap:: %s%n", superFlowMap);

        pcap.close();
    }
}
