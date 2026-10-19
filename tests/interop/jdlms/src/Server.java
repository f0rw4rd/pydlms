// A jDLMS DlmsServer with a small representative object model, for the
// pydlms client sweep.
//
// TCP wrapper on port 4059, logical device 1 (server SAP 1). Clients:
//   16  no authentication
//   17  LLS, password LLS_PASSWORD
//    1  HLS mechanism 5 (GMAC), AES-GCM-128, authenticated + encrypted,
//       EK/AK below; server system title "OMC" + 0x0000000001.
// The keys are the public test keys used throughout pydlms's tests, never
// real meter keys.

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.openmuc.jdlms.AttributeAccessMode;
import org.openmuc.jdlms.AuthenticationMechanism;
import org.openmuc.jdlms.CosemAttribute;
import org.openmuc.jdlms.CosemClass;
import org.openmuc.jdlms.CosemInterfaceObject;
import org.openmuc.jdlms.CosemMethod;
import org.openmuc.jdlms.DlmsServer;
import org.openmuc.jdlms.IllegalAttributeAccessException;
import org.openmuc.jdlms.AccessResultCode;
import org.openmuc.jdlms.LogicalDevice;
import org.openmuc.jdlms.SecuritySuite;
import org.openmuc.jdlms.SecuritySuite.EncryptionMechanism;
import org.openmuc.jdlms.SecuritySuite.SecurityPolicy;
import org.openmuc.jdlms.SelectiveAccessDescription;
import org.openmuc.jdlms.datatypes.DataObject;
import org.openmuc.jdlms.datatypes.DataObject.Type;

public final class Server {

    static final byte[] EK = Oracle.hex("000102030405060708090A0B0C0D0E0F");
    static final byte[] AK = Oracle.hex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");
    static final byte[] KEK = Oracle.hex("101112131415161718191A1B1C1D1E1F");
    static final byte[] LLS_PASSWORD = "JDLMSLLS".getBytes(StandardCharsets.US_ASCII);

    public static void run(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 4059;
        LogicalDevice ld = new LogicalDevice(1, "OMCJDLMS0001", "OMC", 1L);
        ld.setMasterKey(KEK);
        ld.addRestriction(16, SecuritySuite.builder().setAuthenticationMechanism(AuthenticationMechanism.NONE).build());
        ld.addRestriction(17, SecuritySuite.builder()
                .setAuthenticationMechanism(AuthenticationMechanism.LOW)
                .setPassword(LLS_PASSWORD)
                .build());
        ld.addRestriction(1, SecuritySuite.builder()
                .setAuthenticationMechanism(AuthenticationMechanism.HLS5_GMAC)
                .setEncryptionMechanism(EncryptionMechanism.AES_GCM_128)
                .setGlobalUnicastEncryptionKey(EK)
                .setAuthenticationKey(AK)
                .setSecurityPolicy(SecurityPolicy.AUTHENTICATED_AND_ENCRYPTED)
                .build());

        byte[] big = new byte[1000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }
        ld.registerCosemObject(
                new Data("0.0.96.1.0.255", DataObject.newOctetStringData("JDLMS-0001".getBytes(StandardCharsets.US_ASCII))),
                new Data("0.0.96.1.1.255", DataObject.newOctetStringData(big)),
                new Data("0.0.96.14.0.255", DataObject.newUInteger8Data((short) 2)),
                new Register("1.0.1.8.0.255", DataObject.newUInteger32Data(12345678L), 0, 30),
                new Register("1.0.32.7.0.255", DataObject.newUInteger16Data(2301), -1, 35),
                new Register("1.0.31.7.0.255", DataObject.newInteger16Data((short) -523), -2, 33),
                new Clock(), new Profile(), new Disconnect());

        DlmsServer server = DlmsServer.tcpServerBuilder(port).registerLogicalDevice(ld).build();
        System.err.println("jdlms server listening on " + port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                server.close();
            } catch (Exception e) {
                // exiting anyway
            }
        }));
        Thread.currentThread().join();
    }

    static DataObject dateTime(ZonedDateTime t) {
        return DataObject.newOctetStringData(dateTimeBytes(t));
    }

    static byte[] dateTimeBytes(ZonedDateTime t) {
        int deviation = -t.getOffset().getTotalSeconds() / 60; // Blue Book 4.1.6.1: UTC - local
        return ByteBuffer.allocate(12)
                .putShort((short) t.getYear())
                .put((byte) t.getMonthValue())
                .put((byte) t.getDayOfMonth())
                .put((byte) t.getDayOfWeek().getValue())
                .put((byte) t.getHour())
                .put((byte) t.getMinute())
                .put((byte) t.getSecond())
                .put((byte) 0)
                .putShort((short) deviation)
                .put((byte) 0)
                .array();
    }

    static DataObject captureObject(int classId, String obis, int attribute) {
        return DataObject.newStructureData(DataObject.newUInteger16Data(classId),
                DataObject.newOctetStringData(obisBytes(obis)), DataObject.newInteger8Data((byte) attribute),
                DataObject.newUInteger16Data(0));
    }

    static byte[] obisBytes(String obis) {
        String[] p = obis.split("\\.");
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) {
            b[i] = (byte) Integer.parseInt(p[i]);
        }
        return b;
    }

    @CosemClass(id = 1)
    public static class Data extends CosemInterfaceObject {
        @CosemAttribute(id = 2)
        private DataObject value;

        public Data(String obis, DataObject value) {
            super(obis);
            this.value = value;
        }
    }

    @CosemClass(id = 3)
    public static class Register extends CosemInterfaceObject {
        @CosemAttribute(id = 2)
        private DataObject value;

        @CosemAttribute(id = 3, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject scalerUnit;

        public Register(String obis, DataObject value, int scaler, int unit) {
            super(obis);
            this.value = value;
            this.scalerUnit = DataObject.newStructureData(DataObject.newInteger8Data((byte) scaler),
                    DataObject.newEnumerateData(unit));
        }
    }

    /** Blue Book 4.5.1 Clock (class 8, version 0); time is UTC. */
    @CosemClass(id = 8)
    public static class Clock extends CosemInterfaceObject {
        @CosemAttribute(id = 2, type = Type.OCTET_STRING)
        private DataObject time;
        @CosemAttribute(id = 3, type = Type.LONG_INTEGER)
        private DataObject timeZone = DataObject.newInteger16Data((short) 0);
        @CosemAttribute(id = 4, type = Type.UNSIGNED)
        private DataObject status = DataObject.newUInteger8Data((short) 0);
        @CosemAttribute(id = 5, type = Type.OCTET_STRING)
        private DataObject daylightSavingsBegin = DataObject
                .newOctetStringData(Oracle.hex("ffff03fe0702000000800000"));
        @CosemAttribute(id = 6, type = Type.OCTET_STRING)
        private DataObject daylightSavingsEnd = DataObject.newOctetStringData(Oracle.hex("ffff0afe0703000000800000"));
        @CosemAttribute(id = 7, type = Type.INTEGER)
        private DataObject daylightSavingsDeviation = DataObject.newInteger8Data((byte) 60);
        @CosemAttribute(id = 8, type = Type.BOOLEAN)
        private DataObject daylightSavingsEnabled = DataObject.newBoolData(false);
        @CosemAttribute(id = 9, type = Type.ENUMERATE)
        private DataObject clockBase = DataObject.newEnumerateData(1);

        public Clock() {
            super("0.0.1.0.0.255");
        }

        public DataObject getTime() {
            return dateTime(ZonedDateTime.now(ZoneOffset.UTC).withNano(0));
        }

        public void setTime(DataObject value) throws IllegalAttributeAccessException {
            // accepted and ignored: the container clock is the source of truth
        }
    }

    /** Blue Book 4.3.6 Profile generic (class 7, version 1), 10 rows, 15 min. */
    @CosemClass(id = 7, version = 1)
    public static class Profile extends CosemInterfaceObject {
        static final int ROWS = 10;
        static final ZonedDateTime START = ZonedDateTime.of(2024, 5, 1, 0, 0, 0, 0, ZoneOffset.UTC);

        @CosemAttribute(id = 2, accessMode = AttributeAccessMode.READ_ONLY, selector = { 1, 2 })
        private DataObject buffer;
        @CosemAttribute(id = 3, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject captureObjects = DataObject.newArrayData(
                Arrays.asList(captureObject(8, "0.0.1.0.0.255", 2), captureObject(3, "1.0.1.8.0.255", 2)));
        @CosemAttribute(id = 4, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject capturePeriod = DataObject.newUInteger32Data(900);
        @CosemAttribute(id = 5, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject sortMethod = DataObject.newEnumerateData(1);
        @CosemAttribute(id = 6, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject sortObject = captureObject(0, "0.0.0.0.0.0", 0);
        @CosemAttribute(id = 7, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject entriesInUse = DataObject.newUInteger32Data(ROWS);
        @CosemAttribute(id = 8, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject profileEntries = DataObject.newUInteger32Data(ROWS);

        public Profile() {
            super("1.0.99.1.0.255");
        }

        static List<List<DataObject>> rows() {
            List<List<DataObject>> rows = new ArrayList<>();
            for (int i = 0; i < ROWS; i++) {
                rows.add(Arrays.asList(dateTime(START.plusMinutes(15L * i)),
                        DataObject.newUInteger32Data(1000L + 7L * i)));
            }
            return rows;
        }

        /** Range (1) and entry (2) selection, Blue Book 4.3.6 attribute 2. */
        public DataObject getBuffer(SelectiveAccessDescription access) throws IllegalAttributeAccessException {
            List<List<DataObject>> rows = rows();
            int fromCol = 0;
            int toCol = 2;
            boolean[] cols = null;
            if (access != null) {
                List<DataObject> p = access.getAccessParameter().getValue();
                if (access.getAccessSelector() == 2) {
                    int from = ((Number) p.get(0).getValue()).intValue();
                    int to = ((Number) p.get(1).getValue()).intValue();
                    int fc = ((Number) p.get(2).getValue()).intValue();
                    int tc = ((Number) p.get(3).getValue()).intValue();
                    to = to == 0 ? rows.size() : Math.min(to, rows.size());
                    if (from < 1 || from > to) {
                        rows = new ArrayList<>();
                    }
                    else {
                        rows = rows.subList(from - 1, to);
                    }
                    fromCol = Math.max(fc, 1) - 1;
                    toCol = tc == 0 ? 2 : Math.min(tc, 2);
                }
                else if (access.getAccessSelector() == 1) {
                    byte[] lo = p.get(1).getValue();
                    byte[] hi = p.get(2).getValue();
                    List<List<DataObject>> kept = new ArrayList<>();
                    for (List<DataObject> row : rows) {
                        byte[] t = row.get(0).getValue();
                        if (compare(t, lo) >= 0 && compare(t, hi) <= 0) {
                            kept.add(row);
                        }
                    }
                    rows = kept;
                    List<DataObject> selected = p.get(3).getValue();
                    if (!selected.isEmpty()) {
                        cols = new boolean[2];
                        for (DataObject s : selected) {
                            List<DataObject> c = s.getValue();
                            byte[] ln = c.get(1).getValue();
                            cols[Arrays.equals(ln, obisBytes("0.0.1.0.0.255")) ? 0 : 1] = true;
                        }
                    }
                }
                else {
                    throw new IllegalAttributeAccessException(AccessResultCode.OTHER_REASON);
                }
            }
            List<DataObject> out = new ArrayList<>();
            for (List<DataObject> row : rows) {
                List<DataObject> r = new ArrayList<>();
                for (int c = fromCol; c < toCol; c++) {
                    if (cols == null || cols[c]) {
                        r.add(row.get(c));
                    }
                }
                out.add(DataObject.newStructureData(r));
            }
            return DataObject.newArrayData(out);
        }

        /** date-time order on year..second, skipping day-of-week (octet 5). */
        static int compare(byte[] a, byte[] b) {
            int[] idx = { 0, 1, 2, 3, 5, 6, 7 };
            for (int i : idx) {
                int d = (a[i] & 0xff) - (b[i] & 0xff);
                if (d != 0) {
                    return d;
                }
            }
            return 0;
        }
    }

    /** Blue Book 4.5.8 Disconnect control (class 70, version 0). */
    @CosemClass(id = 70)
    public static class Disconnect extends CosemInterfaceObject {
        @CosemAttribute(id = 2, type = Type.BOOLEAN, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject outputState = DataObject.newBoolData(true);
        @CosemAttribute(id = 3, type = Type.ENUMERATE, accessMode = AttributeAccessMode.READ_ONLY)
        private DataObject controlState = DataObject.newEnumerateData(1);
        @CosemAttribute(id = 4, type = Type.ENUMERATE)
        private DataObject controlMode = DataObject.newEnumerateData(1);

        public Disconnect() {
            super("0.0.96.3.10.255");
        }

        @CosemMethod(id = 1, consumes = Type.INTEGER)
        public void remoteDisconnect(DataObject param) {
            outputState = DataObject.newBoolData(false);
            controlState = DataObject.newEnumerateData(0);
        }

        @CosemMethod(id = 2, consumes = Type.INTEGER)
        public void remoteReconnect(DataObject param) {
            outputState = DataObject.newBoolData(true);
            controlState = DataObject.newEnumerateData(1);
        }
    }
}
