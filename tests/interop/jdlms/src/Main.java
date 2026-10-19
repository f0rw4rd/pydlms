// Entry point of the pydlms-interop-jdlms image: oracle (default), server, client.

public final class Main {

    static final String JDLMS_VERSION = "1.8.0";

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "oracle";
        String[] rest = java.util.Arrays.copyOfRange(args, Math.min(1, args.length), args.length);
        switch (mode) {
        case "oracle":
            Oracle.run();
            break;
        case "server":
            Server.run(rest);
            break;
        case "client":
            System.exit(Client.run(rest));
            break;
        default:
            System.err.println("usage: [oracle | server [none|lls|hls5] | client HOST PORT [none|lls|hls5]]");
            System.exit(2);
        }
    }
}
