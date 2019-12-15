package nettrack;

import org.pcap4j.core.*;
import org.pcap4j.util.NifSelector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class App {
    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException, InterruptedException {
        PcapNetworkInterface device = getNetworkDevice(); //selecting the device to track packets on
        System.out.println("You chose: " + device);

        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        int snapshotLength = 65536; // in bytes
        int readTimeout = 50; // in milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        PcapDumper dumper = handle.dumpOpen("res/out.pcap");

        PacketListener listener = packet -> { //packet listener
            System.out.println(handle.getTimestamp());
            System.out.println(packet);

            try {
                dumper.dump(packet, handle.getTimestamp()); //dumping packets to pcap file
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        };

        try {
            int maxPackets = 100;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        dumper.close();
        handle.close();

        final Process p = Runtime.getRuntime().exec("cmd /c /res/tshark -V -r res/out.pcap > res/output.txt");

        new Thread(() -> {
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = null;

            try {
                while ((line = input.readLine()) != null)
                    System.out.println(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        p.waitFor();
    }
}
