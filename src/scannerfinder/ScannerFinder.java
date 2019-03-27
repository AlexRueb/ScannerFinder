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
        // TODO code application logic here
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

        pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

            /**
             * We purposely define and allocate our working tcp header (accessor)
             * outside the dispatch function and thus the libpcap loop, as this type
             * of object is reusable and it would be a very big waist of time and
             * resources to allocate it per every dispatch of a packet. We mark it
             * final since we do not plan on allocating any other instances of Tcp.
             */
            final Tcp tcp = new Tcp();

            /*
             * Same thing for our http header
             */
            final Http http = new Http();

            /**
             * Our custom handler that will receive all the packets libpcap will
             * dispatch to us. This handler is inside a libpcap loop and will receive
             * exactly 10 packets as we specified on the Pcap.loop(10, ...) line
             * above.
             *
             * @param packet
             *          a packet from our capture file
             * @param errbuf
             *          our custom user parameter which we chose to be a StringBuilder
             *          object, but could have chosen anything else we wanted passed
             *          into our handler by libpcap
             */
            public void nextPacket(JPacket packet, StringBuilder errbuf) {

                final JFlowKey key = packet.getState().getFlowKey();

                JFlow flow = flows.get(key);
                if(flow == null){
                    flows.put(key, flow = new JFlow(key));
                }

                flow.add(new PcapPacket(packet));

                if (packet.hasHeader(Tcp.ID)) {

                    /*
                     * Now get our tcp header definition (accessor) peered with actual
                     * memory that holds the tcp header within the packet.
                     */
                    packet.getHeader(tcp);

                    System.out.printf("tcp.dst_port=%d%n", tcp.destination());
                    System.out.printf("tcp.src_port=%d%n", tcp.source());
                    System.out.printf("tcp.ack=%x%n", tcp.ack());

                }

                if (packet.hasHeader(tcp)) {
                    System.out.printf("tcp header::%s%n", tcp.toString());
                    System.out.println("TCP Flags: " + tcp.flags());
                }

                if (packet.hasHeader(tcp) && packet.hasHeader(http)) {

                    System.out.printf("http header::%s%n", http);
                }

//                flows.keySet().forEach((k) -> System.out.println(k.getIds()));
            }

        }, errbuf);

//        for (int i = 0; i < 50; i++) {
//            pcap.nextEx(packet);
//            final JFlowKey key = packet.getState().getFlowKey();
//
//            JFlow flow = flows.get(key);
//            if (flow == null) {
//                flows.put(key, flow = new JFlow(key));
//            }
//
//            flow.add(new PcapPacket(packet));
//        }

//        for (JFlow flow : flows.values()) {
//
//            System.out.printf("Flow %s: ", flow.getKey().toDebugString());
//            if (flow.isReversable()) {
//
//                List<JPacket> forward = flow.getForward();
//                for (JPacket p : forward) {
//                    System.out.printf("%d, ", p.getFrameNumber());
//                }
//                System.out.println();
//
//                List<JPacket> reverse = flow.getReverse();
//                for (JPacket p : reverse) {
//                    System.out.printf("%d, ", p.getFrameNumber());
//                }
//            } else {
//                for (JPacket p : flow.getAll()) {
//                    System.out.printf("%d, ", p.getFrameNumber());
//                }
//            }
//            System.out.println();
//        }
//        JFlowMap superFlowMap = new JFlowMap();
//        pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);
//
//        System.out.printf("superFlowMap:: %s%n", superFlowMap);
//
//        pcap.close();
    }
}
