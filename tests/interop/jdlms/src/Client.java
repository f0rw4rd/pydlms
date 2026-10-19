// jDLMS client against a pydlms simulator (phase 4 of interop-plan.md).
//
//   client HOST PORT [none|lls|hls5] [SECRET-or-EK [AK]]
//
// Associates, reads the association object list, every Register value and
// scaler_unit, the clock, and a profile buffer with entry and range
// selective access. Prints one JSON report on stdout and exits 0 when the
// association worked (individual read failures are in the report).

import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.openmuc.jdlms.AttributeAddress;
import org.openmuc.jdlms.AuthenticationMechanism;
import org.openmuc.jdlms.DlmsConnection;
import org.openmuc.jdlms.GetResult;
import org.openmuc.jdlms.AccessResultCode;
import org.openmuc.jdlms.SecuritySuite;
import org.openmuc.jdlms.SecuritySuite.EncryptionMechanism;
import org.openmuc.jdlms.SecuritySuite.SecurityPolicy;
import org.openmuc.jdlms.SelectiveAccessDescription;
import org.openmuc.jdlms.TcpConnectionBuilder;
import org.openmuc.jdlms.datatypes.DataObject;

public final class Client {

    public static int run(String[] args) throws Exception {
        PrintStream out = new PrintStream(System.out, true, "UTF-8");
        System.setOut(System.err);
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String mode = args.length > 2 ? args[2] : "none";
        String profileObis = System.getenv().getOrDefault("PROFILE", "1.0.99.1.0.255");

        TcpConnectionBuilder b = new TcpConnectionBuilder(InetAddress.getByName(host)).setPort(port)
                .setLogicalDeviceId(1)
                .setResponseTimeout(10000);
        switch (mode) {
        case "lls":
            b.setClientId(17)
                    .setSecuritySuite(SecuritySuite.builder()
                            .setAuthenticationMechanism(AuthenticationMechanism.LOW)
                            .setPassword(args[3].getBytes(StandardCharsets.US_ASCII))
                            .build());
            break;
        case "hls5":
            b.setClientId(1)
                    .setSystemTitle("JDL", 1L)
                    .setSecuritySuite(SecuritySuite.builder()
                            .setAuthenticationMechanism(AuthenticationMechanism.HLS5_GMAC)
                            .setEncryptionMechanism(EncryptionMechanism.AES_GCM_128)
                            .setGlobalUnicastEncryptionKey(Oracle.hex(args[3]))
                            .setAuthenticationKey(Oracle.hex(args[4]))
                            .setSecurityPolicy(SecurityPolicy.AUTHENTICATED_AND_ENCRYPTED)
                            .build());
            break;
        default:
            b.setClientId(16);
        }

        JsonObject report = new JsonObject();
        JsonObject reads = new JsonObject();
        report.add("reads", reads);
        try (DlmsConnection c = b.build()) {
            report.addProperty("associated", true);
            GetResult list = c.get(new AttributeAddress(15, "0.0.40.0.0.255", 2));
            record(reads, "0.0.40.0.0.255/15/2", list, false);
            List<String[]> registers = new ArrayList<>();
            JsonArray objects = new JsonArray();
            if (list.getResultCode() == AccessResultCode.SUCCESS) {
                List<DataObject> entries = list.getResultData().getValue();
                for (DataObject e : entries) {
                    List<DataObject> f = e.getValue();
                    int classId = ((Number) f.get(0).getValue()).intValue();
                    String obis = obis(f.get(2).getValue());
                    objects.add(classId + "/" + obis);
                    if (classId == 3) {
                        registers.add(new String[] { obis });
                    }
                }
            }
            report.add("objects", objects);
            for (String[] r : registers) {
                for (int attr : new int[] { 2, 3 }) {
                    record(reads, r[0] + "/3/" + attr, c.get(new AttributeAddress(3, r[0], attr)), true);
                }
            }
            record(reads, "0.0.1.0.0.255/8/2", c.get(new AttributeAddress(8, "0.0.1.0.0.255", 2)), true);
            record(reads, profileObis + "/7/3", c.get(new AttributeAddress(7, profileObis, 3)), true);
            record(reads, profileObis + "/7/2", c.get(new AttributeAddress(7, profileObis, 2)), true);
            DataObject entry = DataObject.newStructureData(DataObject.newUInteger32Data(1),
                    DataObject.newUInteger32Data(2), DataObject.newUInteger16Data(1), DataObject.newUInteger16Data(0));
            record(reads, profileObis + "/7/2?entry=1-2",
                    c.get(new AttributeAddress(7, profileObis, 2, new SelectiveAccessDescription(2, entry))), true);
            String from = System.getenv().getOrDefault("RANGE_FROM", "07e8050103000000ff800000");
            String to = System.getenv().getOrDefault("RANGE_TO", "07e8050103001e00ff800000");
            DataObject range = DataObject.newStructureData(
                    Server.captureObject(8, "0.0.1.0.0.255", 2),
                    DataObject.newOctetStringData(Oracle.hex(from)), DataObject.newOctetStringData(Oracle.hex(to)),
                    DataObject.newArrayData(new ArrayList<>()));
            record(reads, profileObis + "/7/2?range",
                    c.get(new AttributeAddress(7, profileObis, 2, new SelectiveAccessDescription(1, range))), true);
        } catch (Exception e) {
            report.addProperty("associated", reads.size() > 0);
            report.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        out.println(report.toString());
        out.flush();
        return report.get("associated").getAsBoolean() ? 0 : 1;
    }

    static void record(JsonObject reads, String key, GetResult r, boolean withValue) {
        JsonObject j = new JsonObject();
        j.addProperty("result", r.getResultCode().name());
        if (r.getResultCode() == AccessResultCode.SUCCESS) {
            if (withValue) {
                j.add("value", Oracle.objJson(r.getResultData()));
            }
            else {
                List<DataObject> l = r.getResultData().getValue();
                j.addProperty("count", l.size());
            }
        }
        reads.add(key, j);
    }

    static String obis(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            sb.append(i == 0 ? "" : ".").append(b[i] & 0xff);
        }
        return sb.toString();
    }
}
