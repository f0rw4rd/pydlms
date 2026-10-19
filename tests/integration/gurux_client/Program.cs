// Generates general-ciphering / general-signing request APDUs with the Gurux
// client library, for pydlms to decrypt and verify (independent-implementation
// test of pydlms' inbound 0xDD/0xDF handling). Test harness only, built and
// run by tests/integration/gurux_client/Dockerfile against the Gurux library.
//
// The originator is "GXClient", the recipient 4752580000000001, suite 1,
// security 0x30, invocation counter 77, keys as in test_gurux_client.py.
//
// args: mode clientSigningPriv(hex32) recipientKaPub(hex64) recipientSigningPub(hex64)
//       [clientKaPriv(hex32) transactionId(hex)]   (static-unified only)
// mode: general-ciphering (one-pass DH) | general-signing | static-unified
//
// translate simple|standard [blockCipherKey authenticationKey]: GXDLMSTranslator
// as an XML oracle. Reads stdin lines "P <apdu hex>" (PduToXml) or
// "X <base64 xml>" (XmlToPdu) and answers each with one line: "X <base64 xml>",
// "P <hex>" or "E <error>".
using System;
using System.Collections.Generic;
using Gurux.DLMS;
using Gurux.DLMS.Ecdsa;
using Gurux.DLMS.Ecdsa.Enums;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using Gurux.DLMS.Secure;

class Program
{
    static byte[] Hex(string s) => Convert.FromHexString(s);

    static int Translate(string[] args)
    {
        var t = new GXDLMSTranslator(args[1] == "standard"
            ? TranslatorOutputType.StandardXml : TranslatorOutputType.SimpleXml);
        t.Comments = true;
        t.OmitXmlDeclaration = true;
        t.OmitXmlNameSpace = true;
        if (args.Length > 3)
        {
            t.BlockCipherKey = Hex(args[2]);
            t.AuthenticationKey = Hex(args[3]);
        }
        string line;
        while ((line = Console.In.ReadLine()) != null)
        {
            if (line.Length < 2)
            {
                continue;
            }
            try
            {
                if (line[0] == 'P')
                {
                    string xml = t.PduToXml(Hex(line.Substring(2).Trim()));
                    Console.WriteLine("X " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(xml)));
                }
                else
                {
                    string xml = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(2).Trim()));
                    Console.WriteLine("P " + Convert.ToHexString(t.XmlToPdu(xml)));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("E " + e.GetType().Name + ": " + e.Message.Replace("\n", " "));
            }
            Console.Out.Flush();
        }
        return 0;
    }

    static int Main(string[] args)
    {
        string mode = args[0];
        if (mode == "translate")
        {
            return Translate(args);
        }
        if (mode == "kdf")
        {
            // kdf ownPriv(hex32|hex48) peerPub(hex64|hex96) partyU(hex) partyV(hex):
            // Gurux ECDH and its SP 800-56A KDF (suite from the key size).
            var own = GXPrivateKey.FromRawBytes(Hex(args[1]));
            var peer = GXPublicKey.FromRawBytes(Hex("04" + args[2]));
            bool suite2 = own.Scheme == Ecc.P384;
            byte[] z = new GXEcdsa(own).GenerateSecret(peer);
            // GXSecure is internal; call its 7-argument GenerateKDF by reflection.
            var generateKdf = typeof(GXDLMSClient).Assembly.GetType("Gurux.DLMS.Secure.GXSecure")
                .GetMethod("GenerateKDF", new[] {
                    typeof(SecuritySuite), typeof(byte[]), typeof(AlgorithmId), typeof(byte[]),
                    typeof(byte[]), typeof(byte[]), typeof(byte[]) });
            byte[] kdf = (byte[])generateKdf.Invoke(null, new object[] {
                suite2 ? SecuritySuite.Suite2 : SecuritySuite.Suite1, z,
                suite2 ? AlgorithmId.AesGcm256 : AlgorithmId.AesGcm128,
                Hex(args[3]), Hex(args[4]), null, null });
            Console.WriteLine(Convert.ToHexString(z));
            Console.WriteLine(Convert.ToHexString(kdf));
            return 0;
        }
        var signPriv = GXPrivateKey.FromRawBytes(Hex(args[1]));
        var recipientKa = GXPublicKey.FromRawBytes(Hex("04" + args[2]));
        var recipientSign = GXPublicKey.FromRawBytes(Hex("04" + args[3]));
        var client = new GXDLMSSecureClient(true, 44, 1, Authentication.None, null, InterfaceType.WRAPPER);
        // P-384 keys select suite 2 (AES-256: 32-octet EK and AK).
        bool useSuite2 = signPriv.Scheme == Ecc.P384;
        client.Ciphering.SecuritySuite = useSuite2 ? SecuritySuite.Suite2 : SecuritySuite.Suite1;
        client.Ciphering.Security = Security.AuthenticationEncryption;
        client.Ciphering.SystemTitle = System.Text.Encoding.ASCII.GetBytes("GXClient");
        client.ServerSystemTitle = Hex("4752580000000001");
        client.Ciphering.BlockCipherKey = Hex(useSuite2
            ? "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
            : "000102030405060708090A0B0C0D0E0F");
        client.Ciphering.AuthenticationKey = Hex(useSuite2
            ? "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
            : "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");
        client.Ciphering.InvocationCounter = 77;
        client.Ciphering.SigningKeyPair = new KeyValuePair<GXPublicKey, GXPrivateKey>(recipientSign, signPriv);
        GXPrivateKey kaPriv = mode == "static-unified" ? GXPrivateKey.FromRawBytes(Hex(args[4])) : null;
        client.Ciphering.KeyAgreementKeyPair = new KeyValuePair<GXPublicKey, GXPrivateKey>(recipientKa, kaPriv);
        switch (mode)
        {
            case "general-signing":
                client.Ciphering.Signing = Signing.GeneralSigning;
                break;
            case "static-unified":
                client.Ciphering.Signing = Signing.StaticUnifiedModel;
                client.Ciphering.TransactionId = Hex(args[5]);
                break;
            default:
                client.Ciphering.Signing = Signing.OnePassDiffieHellman;
                break;
        }
        // Pretend the association is open (Cipher1 is only used then).
        typeof(GXDLMSSettings).GetField("Connected",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            .SetValue(client.Settings, ConnectionState.Dlms);
        // Normally learnt from the AARE.
        typeof(GXDLMSSettings).GetProperty("SourceSystemTitle",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            .SetValue(client.Settings, Hex("4752580000000001"));
        byte[][] frames = client.Read(new GXDLMSData("0.0.42.0.0.255"), 2);
        foreach (byte[] frame in frames)
        {
            Console.WriteLine(Convert.ToHexString(frame));
        }
        return 0;
    }
}
