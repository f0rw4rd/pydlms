// Oracle adapter for Gurux.DLMS.Net (tests/interop/PROTOCOL.md): one request
// per stdin line, one JSON object per stdout line. Test harness only; built
// and run by tests/interop/gurux-net/Dockerfile against the pinned Gurux
// library, as a separate process. No Gurux code is copied into pydlms.
//
// Which Gurux code answers each op:
//   data         accept/reject: GXCommon.GetData, the decoder GXDLMSClient
//                uses for every attribute value (strict, no XML), plus a
//                trailing-octet check; the typed tree: GXDLMSTranslator.DataToXml
//                (same decoder, XML mode), mapped to the protocol's model.
//   encode-data  GXCommon.SetData per leaf, GXCommon.SetObjectCount for
//                array/structure headers. Date types go bytes -> GXDateTime
//                (GXDLMSClient.ChangeType) -> SetData, i.e. through Gurux's
//                date model. Compact arrays: unsupported (SetData throws).
//   apdu         GXDLMSTranslator.PduToXml, a subset of fields mapped.
//   push         acceptance: GXDLMSSecureClient.GetData (PDU interface, keys
//                set on Ciphering), the path a Gurux client app uses for an
//                inbound DataNotification; tree: PduToXml with the same keys.
//   decrypt      GXSecure.DecryptAesGcm (what GXCiphering.Decrypt calls).
//   compact-data GXDLMSCompactData.GetValues (template description plus
//                compact buffer -> the captured rows, decoded the way a
//                Gurux client decodes a Compact data object), typed by
//                GXDLMSCompactData.GetDataTypes on the same template.
// The XML paths swallow some decode errors and leave a comment instead;
// such comments ("Error...", "Invalid...", "Unknown tag", ...) are reported
// as a rejection.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Internal;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using Gurux.DLMS.Secure;

class UnsupportedException : Exception
{
    public UnsupportedException(string message) : base(message) { }
}

class RejectException : Exception
{
    public RejectException(string message) : base(message) { }
}

static class Program
{
    static readonly string[] Ops = { "data", "encode-data", "apdu", "push", "decrypt", "compact-data" };

    static byte[] Hex(string s) => Convert.FromHexString(s);
    static string ToHex(byte[] b) => Convert.ToHexString(b ?? new byte[0]).ToLowerInvariant();

    static int Main(string[] argv)
    {
        if (argv.Length > 0 && argv[0] == "client")
        {
            return ReverseClient.Run(argv);
        }
        string line;
        while ((line = Console.In.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length == 0)
            {
                continue;
            }
            JsonObject reply;
            try
            {
                reply = Answer(line);
            }
            catch (UnsupportedException e)
            {
                reply = new JsonObject { ["ok"] = false, ["unsupported"] = true, ["error"] = e.Message };
            }
            catch (Exception e)
            {
                Exception inner = e is System.Reflection.TargetInvocationException && e.InnerException != null
                    ? e.InnerException : e;
                reply = new JsonObject
                {
                    ["ok"] = false,
                    ["error"] = inner.GetType().Name + ": " + inner.Message.Replace("\n", " "),
                };
            }
            Console.Out.WriteLine(reply.ToJsonString());
            Console.Out.Flush();
        }
        return 0;
    }

    static JsonObject Answer(string line)
    {
        int sp = line.IndexOf(' ');
        string op = sp < 0 ? line : line.Substring(0, sp);
        string rest = sp < 0 ? "" : line.Substring(sp + 1).Trim();
        string[] args = rest.Length == 0 ? new string[0] : rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (op == "hello")
        {
            var ops = new JsonArray();
            foreach (string o in Ops)
            {
                ops.Add(o);
            }
            return new JsonObject
            {
                ["ok"] = true,
                ["library"] = "Gurux.DLMS.Net",
                ["version"] = Environment.GetEnvironmentVariable("GURUX_COMMIT") ?? "unknown",
                ["ops"] = ops,
            };
        }
        JsonNode result;
        switch (op)
        {
            case "data":
                result = OpData(args[0]);
                break;
            case "encode-data":
                result = new JsonObject { ["hex"] = ToHex(EncodeData(JsonNode.Parse(rest))) };
                break;
            case "apdu":
                result = OpApdu(args[0]);
                break;
            case "push":
                result = OpPush(args[0], args.Length > 1 ? args[1] : null, args.Length > 2 ? args[2] : null);
                break;
            case "decrypt":
                result = new JsonObject { ["plaintext"] = ToHex(Decrypt(args[0], args[1], args[2], Hex(args[3]))) };
                break;
            case "compact-data":
                result = OpCompactData(args[0], args.Length > 1 ? args[1] : "-");
                break;
            case "xml": // debugging aid, not part of the protocol
                result = Translator(args.Length > 1 ? args[1] : null, args.Length > 2 ? args[2] : null).PduToXml(Hex(args[0]));
                break;
            case "dataxml": // debugging aid
                Translator(null, null).DataToXml(Hex(args[0]), out string x);
                result = x;
                break;
            default:
                throw new UnsupportedException("unknown op " + op);
        }
        return new JsonObject { ["ok"] = true, ["result"] = result };
    }

    // ---------------------------------------------------------------- data

    static GXDLMSTranslator Translator(string ek, string ak)
    {
        var t = new GXDLMSTranslator(TranslatorOutputType.SimpleXml);
        t.Comments = true;
        t.Hex = false;
        t.ShowStringAsHex = true;
        t.OmitXmlDeclaration = true;
        t.OmitXmlNameSpace = true;
        if (!string.IsNullOrEmpty(ek))
        {
            t.BlockCipherKey = Hex(ek);
        }
        if (!string.IsNullOrEmpty(ak))
        {
            t.AuthenticationKey = Hex(ak);
        }
        return t;
    }

    static readonly string[] ErrorMarks =
    {
        "Error", "ERROR", "Invalid", "Unknown tag", "Decrypt failed", "is missing", "Extra data",
    };

    static XElement ParseXml(string xml)
    {
        // Gurux comments may contain "--" (e.g. a decoded date), which is not
        // well-formed XML; the comments are informational, so neutralise it.
        xml = System.Text.RegularExpressions.Regex.Replace(xml, "<!--(.*?)-->",
            m => "<!--" + m.Groups[1].Value.Replace("--", "- -").TrimEnd('-') + " -->",
            System.Text.RegularExpressions.RegexOptions.Singleline);
        XElement root = XElement.Parse("<root>" + xml + "</root>");
        foreach (XComment c in root.DescendantNodes().OfType<XComment>())
        {
            string text = c.Value.Trim();
            foreach (string mark in ErrorMarks)
            {
                if (text.StartsWith(mark) || (mark == "is missing" && text.Contains(mark)))
                {
                    throw new RejectException("translator: " + text.Replace("\n", " ").Replace("\r", ""));
                }
            }
        }
        return root;
    }

    static JsonNode OpData(string hex)
    {
        byte[] raw = Hex(hex);
        var bb = new GXByteBuffer(raw);
        var info = new GXDataInfo();
        GXCommon.GetData(null, bb, info);
        if (!info.Complete)
        {
            throw new RejectException("GetData: incomplete value");
        }
        if (bb.Position != bb.Size)
        {
            throw new RejectException((bb.Size - bb.Position) + " trailing octets");
        }
        if (raw[0] == (byte)DataType.CompactArray)
        {
            return CompactArray(raw, info.Type == DataType.CompactArray ? GetValueAgain(raw) : null);
        }
        Translator(null, null).DataToXml(raw, out string xml);
        XElement root = ParseXml(xml);
        try
        {
            return DataNode(Elements(root).Single());
        }
        catch (NotMappedException e)
        {
            // Gurux accepted the value (above) but the tree cannot be mapped.
            throw new UnsupportedException(e.Message);
        }
    }

    // ------------------------------------------------------- compact-data

    static JsonNode OpCompactData(string template, string buffer)
    {
        byte[] t = template == "-" ? new byte[0] : Hex(template);
        byte[] b = buffer == "-" ? new byte[0] : Hex(buffer);
        List<object> rows = new GXDLMSCompactData().GetValues(t, b);
        List<object> cols = GXDLMSCompactData.GetDataTypes(t);
        if (!(cols is GXStructure))
        {
            throw new RejectException("template description is not a structure");
        }
        var captures = new JsonArray();
        foreach (object row in rows)
        {
            captures.Add(Typed(row, cols));
        }
        return new JsonObject { ["captures"] = captures };
    }

    static object GetValueAgain(byte[] raw)
    {
        return GXCommon.GetData(null, new GXByteBuffer(raw), new GXDataInfo());
    }

    // A top-level compact-array, from Gurux's objects: the contents
    // description from GXCommon.GetCompactArray(onlyDataTypes) (or the single
    // type tag), the items from GXCommon.GetData, typed by that description.
    // (SimpleXml prints the items as "1;2;3" without types.)
    static JsonObject CompactArray(byte[] raw, object value)
    {
        object desc;
        if (raw[1] == (byte)DataType.Structure)
        {
            var bb = new GXByteBuffer(raw);
            bb.Position = 1;
            desc = GXCommon.GetCompactArray(null, bb, new GXDataInfo(), true);
        }
        else
        {
            desc = (DataType)raw[1];
        }
        var items = new JsonArray();
        foreach (object item in (IEnumerable<object>)value)
        {
            items.Add(Typed(item, desc));
        }
        return new JsonObject
        {
            ["t"] = "compact-array",
            ["v"] = new JsonObject { ["description"] = Description(desc), ["items"] = items },
        };
    }

    static JsonObject Description(object desc)
    {
        if (desc is DataType dt)
        {
            return new JsonObject { ["t"] = TypeName(dt) };
        }
        var list = (List<object>)desc;
        if (desc is GXArray)
        {
            // GetDataTypes expands array[n] of T into n copies of T.
            if (list.Count == 0)
            {
                throw new UnsupportedException("compact-array: empty array description");
            }
            return new JsonObject { ["t"] = "array", ["count"] = list.Count, ["of"] = Description(list[0]) };
        }
        var members = new JsonArray();
        foreach (object m in list)
        {
            members.Add(Description(m));
        }
        return new JsonObject { ["t"] = "structure", ["members"] = members };
    }

    static string TypeName(DataType dt)
    {
        foreach (var kv in ByName)
        {
            if (kv.Value == dt)
            {
                return kv.Key;
            }
        }
        throw new UnsupportedException("type " + dt);
    }

    // A Gurux .NET value whose A-XDR type is known from the description.
    static JsonObject Typed(object v, object desc)
    {
        if (!(desc is DataType dt))
        {
            var list = (List<object>)desc;
            var values = (List<object>)v;
            var children = new JsonArray();
            for (int i = 0; i != values.Count; ++i)
            {
                children.Add(Typed(values[i], list[Math.Min(i, list.Count - 1)]));
            }
            return new JsonObject { ["t"] = desc is GXArray ? "array" : "structure", ["v"] = children };
        }
        var node = new JsonObject { ["t"] = TypeName(dt) };
        switch (dt)
        {
            case DataType.None:
                node["v"] = null;
                break;
            case DataType.Boolean:
                node["v"] = (bool)v;
                break;
            case DataType.BitString:
                node["v"] = v.ToString();
                break;
            case DataType.OctetString:
                node["v"] = ToHex((byte[])v);
                break;
            case DataType.String:
            case DataType.StringUTF8:
                node["v"] = (string)v;
                break;
            case DataType.Float32:
                node["v"] = ToHex(Reverse(BitConverter.GetBytes((float)v)));
                break;
            case DataType.Float64:
                node["v"] = ToHex(Reverse(BitConverter.GetBytes((double)v)));
                break;
            case DataType.DateTime:
            case DataType.Date:
            case DataType.Time:
                var bb = new GXByteBuffer();
                GXCommon.SetData(null, bb, dt, v);
                node["v"] = ToHex(bb.SubArray(1, bb.Size - 1));
                break;
            case DataType.Enum:
                node["v"] = ((GXEnum)v).Value;
                break;
            case DataType.UInt64:
                node["v"] = Convert.ToUInt64(v);
                break;
            default:
                node["v"] = Convert.ToInt64(v);
                break;
        }
        return node;
    }

    static IEnumerable<XElement> Elements(XElement e) => e.Elements();

    static string Val(XElement e) => (string)e.Attribute("Value");

    static readonly Dictionary<string, string> TypeNames = new Dictionary<string, string>
    {
        ["None"] = "null-data", ["Array"] = "array", ["Structure"] = "structure",
        ["Boolean"] = "boolean", ["BitString"] = "bit-string", ["Int32"] = "double-long",
        ["UInt32"] = "double-long-unsigned", ["OctetString"] = "octet-string",
        ["String"] = "visible-string", ["StringUTF8"] = "utf8-string", ["Bcd"] = "bcd",
        ["Int8"] = "integer", ["Int16"] = "long", ["UInt8"] = "unsigned",
        ["UInt16"] = "long-unsigned", ["CompactArray"] = "compact-array", ["Int64"] = "long64",
        ["UInt64"] = "long64-unsigned", ["Enum"] = "enum", ["Float32"] = "float32",
        ["Float64"] = "float64", ["DateTime"] = "date-time", ["Date"] = "date", ["Time"] = "time",
    };

    static JsonObject DataNode(XElement e)
    {
        string name = e.Name.LocalName;
        if (!TypeNames.TryGetValue(name, out string t))
        {
            throw new RejectException("unknown data element " + name);
        }
        var node = new JsonObject { ["t"] = t };
        string v = Val(e);
        switch (name)
        {
            case "None":
                node["v"] = null;
                break;
            case "Array":
            case "Structure":
                var items = new JsonArray();
                foreach (XElement c in Elements(e))
                {
                    items.Add(DataNode(c));
                }
                node["v"] = items;
                break;
            case "CompactArray":
                throw new NotMappedException("compact-array: the translator's XML drops the item types");
            case "Boolean":
                node["v"] = v == "true" || v == "1";
                break;
            case "BitString":
            case "StringUTF8":
                node["v"] = v ?? "";
                break;
            case "String":
                node["v"] = Encoding.Latin1.GetString(Hex(v ?? ""));
                break;
            case "OctetString":
            case "DateTime":
            case "Date":
            case "Time":
            case "Float32":
            case "Float64":
                node["v"] = (v ?? "").ToLowerInvariant();
                break;
            case "UInt64":
                node["v"] = ulong.Parse(v);
                break;
            default:
                node["v"] = long.Parse(v);
                break;
        }
        return node;
    }

    // --------------------------------------------------------- encode-data

    static readonly Dictionary<string, DataType> ByName = new Dictionary<string, DataType>
    {
        ["null-data"] = DataType.None, ["array"] = DataType.Array, ["structure"] = DataType.Structure,
        ["boolean"] = DataType.Boolean, ["bit-string"] = DataType.BitString,
        ["double-long"] = DataType.Int32, ["double-long-unsigned"] = DataType.UInt32,
        ["octet-string"] = DataType.OctetString, ["visible-string"] = DataType.String,
        ["utf8-string"] = DataType.StringUTF8, ["bcd"] = DataType.Bcd, ["integer"] = DataType.Int8,
        ["long"] = DataType.Int16, ["unsigned"] = DataType.UInt8, ["long-unsigned"] = DataType.UInt16,
        ["compact-array"] = DataType.CompactArray, ["long64"] = DataType.Int64,
        ["long64-unsigned"] = DataType.UInt64, ["enum"] = DataType.Enum,
        ["float32"] = DataType.Float32, ["float64"] = DataType.Float64,
        ["date-time"] = DataType.DateTime, ["date"] = DataType.Date, ["time"] = DataType.Time,
        // decode only: Encode has no delta case and reports them unsupported
        ["delta-integer"] = DataType.DeltaInt8, ["delta-long"] = DataType.DeltaInt16,
        ["delta-double-long"] = DataType.DeltaInt32, ["delta-unsigned"] = DataType.DeltaUInt8,
        ["delta-long-unsigned"] = DataType.DeltaUInt16,
        ["delta-double-long-unsigned"] = DataType.DeltaUInt32,
    };

    static byte[] EncodeData(JsonNode tree)
    {
        var bb = new GXByteBuffer();
        Encode(tree, bb);
        return bb.Array();
    }

    static void Encode(JsonNode node, GXByteBuffer bb)
    {
        DataType type = ByName[(string)node["t"]];
        JsonNode v = node["v"];
        object value;
        switch (type)
        {
            case DataType.Array:
            case DataType.Structure:
                JsonArray items = v.AsArray();
                bb.SetUInt8((byte)type);
                GXCommon.SetObjectCount(items.Count, bb);
                foreach (JsonNode item in items)
                {
                    Encode(item, bb);
                }
                return;
            case DataType.CompactArray:
                throw new UnsupportedException("GXCommon.SetData has no compact-array encoder");
            case DataType.None:
                value = null;
                break;
            case DataType.Boolean:
                value = (bool)v;
                break;
            case DataType.BitString:
            case DataType.String:
            case DataType.StringUTF8:
                value = (string)v;
                break;
            case DataType.OctetString:
                value = Hex((string)v);
                break;
            case DataType.DateTime:
            case DataType.Date:
            case DataType.Time:
                value = GXDLMSClient.ChangeType(Hex((string)v), type, false);
                break;
            case DataType.Float32:
                value = BitConverter.ToSingle(Reverse(Hex((string)v)), 0);
                break;
            case DataType.Float64:
                value = BitConverter.ToDouble(Reverse(Hex((string)v)), 0);
                break;
            case DataType.UInt64:
                value = (ulong)v;
                break;
            case DataType.Int8:
                value = (sbyte)(long)v;
                break;
            case DataType.Int16:
                value = (short)(long)v;
                break;
            case DataType.Int32:
                value = (int)(long)v;
                break;
            case DataType.Int64:
                value = (long)v;
                break;
            case DataType.UInt8:
            case DataType.Enum:
            case DataType.Bcd:
                value = (byte)(long)v;
                break;
            case DataType.UInt16:
                value = (ushort)(long)v;
                break;
            case DataType.UInt32:
                value = (uint)(long)v;
                break;
            default:
                throw new UnsupportedException("type " + type);
        }
        GXCommon.SetData(null, bb, type, value);
    }

    static byte[] Reverse(byte[] b)
    {
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(b);
        }
        return b;
    }

    // ---------------------------------------------------------------- apdu

    class NotMappedException : Exception
    {
        public NotMappedException(string message) : base(message) { }
    }

    static JsonNode OpApdu(string hex)
    {
        string xml = Translator(null, null).PduToXml(Hex(hex));
        if (xml.StartsWith("<Data=\""))
        {
            // PduToXml's fallback for a command it does not decode.
            throw new UnsupportedException("translator does not decode command 0x" + hex.Substring(0, 2));
        }
        return ApduFromXml(ParseXml(xml));
    }

    // Translator element (the operation itself, below a GetRequest/... wrapper
    // where there is one) -> pydlms kind.
    static readonly Dictionary<string, string> Kinds = new Dictionary<string, string>
    {
        ["GetRequestNormal"] = "get-request-normal",
        ["GetRequestForNextDataBlock"] = "get-request-next",
        ["GetRequestWithList"] = "get-request-with-list",
        ["GetResponseNormal"] = "get-response-normal",
        ["GetResponsewithDataBlock"] = "get-response-with-datablock",
        ["GetResponseWithList"] = "get-response-with-list",
        ["SetRequestNormal"] = "set-request-normal",
        ["SetRequestFirstDataBlock"] = "set-request-with-first-datablock",
        ["SetRequestWithDataBlock"] = "set-request-with-datablock",
        ["SetRequestWithList"] = "set-request-with-list",
        ["SetResponseNormal"] = "set-response-normal",
        ["SetResponseDataBlock"] = "set-response-datablock",
        ["SetResponseWithLastDataBlock"] = "set-response-last-datablock",
        ["SetResponseWithList"] = "set-response-with-list",
        ["ActionRequestNormal"] = "action-request-normal",
        ["ActionRequestForNextPBlock"] = "action-request-next-pblock",
        ["ActionRequestWithList"] = "action-request-with-list",
        ["ActionRequestWithFirstBlock"] = "action-request-with-first-pblock",
        ["ActionRequestWithBlock"] = "action-request-with-pblock",
        ["ActionResponseNormal"] = "action-response-normal",
        ["ActionResponseWithPBlock"] = "action-response-with-pblock",
        ["ActionResponseWithList"] = "action-response-with-list",
        ["ActionResponseNextBlock"] = "action-response-next-pblock",
        ["AssociationRequest"] = "aarq",
        ["AssociationResponse"] = "aare",
        ["ReleaseRequest"] = "rlrq",
        ["ReleaseResponse"] = "rlre",
        ["InitiateRequest"] = "initiate-request",
        ["InitiateResponse"] = "initiate-response",
        ["ConfirmedServiceError"] = "confirmed-service-error",
        ["ExceptionResponse"] = "exception-response",
        ["DataNotification"] = "data-notification",
        ["EventNotificationRequest"] = "event-notification-request",
        ["InformationReportRequest"] = "information-report-request",
        ["ReadRequest"] = "read-request",
        ["ReadResponse"] = "read-response",
        ["WriteRequest"] = "write-request",
        ["WriteResponse"] = "write-response",
        ["UnconfirmedWriteRequest"] = "unconfirmed-write-request",
        ["GeneralBlockTransfer"] = "gbt-block",
    };

    static readonly HashSet<string> Wrappers = new HashSet<string>
    {
        "GetRequest", "GetResponse", "SetRequest", "SetResponse", "ActionRequest", "ActionResponse",
    };

    static JsonObject ApduFromXml(XElement root)
    {
        XElement top = Elements(root).Single();
        XElement op = Wrappers.Contains(top.Name.LocalName) ? Elements(top).Single() : top;
        if (!Kinds.TryGetValue(op.Name.LocalName, out string kind))
        {
            throw new UnsupportedException("no mapping for translator element " + op.Name.LocalName);
        }
        var o = new JsonObject { ["kind"] = kind };
        Fields(kind, op, o);
        return o;
    }

    static XElement Child(XElement e, string name) => Elements(e).FirstOrDefault(c => c.Name.LocalName == name);

    static long Int(XElement e) => long.Parse(Val(e));

    // One field at a time: a field the XML does not carry (or that cannot be
    // mapped) is left out; the comparison checks only the keys returned.
    static void Set(JsonObject o, string key, Func<JsonNode> get)
    {
        try
        {
            o[key] = get();
        }
        catch (NotMappedException)
        {
        }
        catch (NullReferenceException)
        {
        }
    }

    static void Fields(string kind, XElement op, JsonObject o)
    {
        if (Child(op, "InvokeIdAndPriority") != null)
        {
            Set(o, "invoke_id", () => Int(Child(op, "InvokeIdAndPriority")));
        }
        if (Child(op, "AttributeDescriptor") != null)
        {
            Set(o, "attribute", () => Descriptor(Child(op, "AttributeDescriptor"), "AttributeId", "attribute_id"));
        }
        if (Child(op, "MethodDescriptor") != null)
        {
            Set(o, "method", () => Descriptor(Child(op, "MethodDescriptor"), "MethodId", "method_id"));
        }
        switch (kind)
        {
            case "get-response-normal":
                Set(o, "result", () => DataResult(Elements(Child(op, "Result")).Single()));
                break;
            case "get-response-with-list":
                Set(o, "results", () => new JsonArray(Elements(Child(op, "Result")).Select(e => (JsonNode)DataResult(e)).ToArray()));
                break;
            case "get-response-with-datablock":
                XElement r = Child(op, "Result");
                Set(o, "last_block", () => Int(Child(r, "LastBlock")) != 0);
                Set(o, "block_number", () => Int(Child(r, "BlockNumber")));
                Set(o, "raw_data", () => Val(Child(Child(r, "Result"), "RawData")).ToLowerInvariant());
                break;
            // get-request-with-list items: not mapped. GetRequestWithList in
            // GXDLMSLNCommandHandlers parses an access selection but never writes
            // it to the XML, so "no selection" cannot be told from "dropped".
            case "set-request-normal":
                Set(o, "value", () => DataNode(Elements(Child(op, "Value")).Single()));
                break;
            case "set-response-normal":
            case "action-response-normal":
                Set(o, "result", () => ErrorCodeValue(Child(op, "Result")));
                break;
            case "set-response-last-datablock":
                Set(o, "result", () => ErrorCodeValue(Child(op, "Result")));
                Set(o, "block_number", () => Int(Child(op, "BlockNumber")));
                break;
            case "action-request-normal":
                if (Child(op, "MethodInvocationParameters") != null)
                {
                    Set(o, "parameters", () => DataNode(Elements(Child(op, "MethodInvocationParameters")).Single()));
                }
                break;
            case "data-notification":
                Set(o, "long_invoke_id", () => Int(Child(op, "LongInvokeIdAndPriority")));
                Set(o, "date_time", () =>
                {
                    string dt = Val(Child(op, "DateTime"));
                    return string.IsNullOrEmpty(dt) ? null : dt.ToLowerInvariant();
                });
                Set(o, "body", () => DataNode(Elements(Child(Child(op, "NotificationBody"), "DataValue")).Single()));
                break;
            case "get-request-next":
            case "set-response-datablock":
            case "action-request-next-pblock":
            case "action-response-next-pblock":
                Set(o, "block_number", () => Int(Child(op, "BlockNumber")));
                break;
            case "exception-response":
                Set(o, "state_error", () => (int)StateErrorValue(Val(Child(op, "StateError"))));
                Set(o, "service_error", () => (int)TranslatorSimpleTags.ValueOfExceptionServiceError(Val(Child(op, "ServiceError"))));
                break;
            case "aarq":
            case "aare":
                Set(o, "application_context", () => Contexts[Val(Child(op, "ApplicationContextName"))]);
                if (Child(op, "MechanismName") != null)
                {
                    Set(o, "mechanism", () => Mechanisms[Val(Child(op, "MechanismName"))]);
                }
                if (kind == "aare")
                {
                    Set(o, "result", () => Int(Child(op, "AssociationResult")));
                    Set(o, "diagnostic_source", () =>
                        Elements(Child(op, "ResultSourceDiagnostic")).Single().Name.LocalName == "ACSEServiceUser" ? 1 : 2);
                    Set(o, "diagnostic", () => Int(Elements(Child(op, "ResultSourceDiagnostic")).Single()));
                    if (Child(op, "RespondingAPTitle") != null)
                    {
                        Set(o, "responding_ap_title", () => Val(Child(op, "RespondingAPTitle")).ToLowerInvariant());
                    }
                }
                else if (Child(op, "CallingAPTitle") != null)
                {
                    Set(o, "calling_ap_title", () => Val(Child(op, "CallingAPTitle")).ToLowerInvariant());
                }
                break;
            case "confirmed-service-error":
                Set(o, "service", () => Int(Child(op, "Service")));
                // The CHOICE index as Gurux's ServiceError enum numbers it.
                Set(o, "error_type", () => (int)(ServiceError)Enum.Parse(typeof(ServiceError),
                    Elements(Child(op, "ServiceError")).Single().Name.LocalName));
                break;
            case "initiate-request":
                Set(o, "dlms_version", () => Int(Child(op, "ProposedDlmsVersionNumber")));
                Set(o, "max_receive_pdu_size", () => Int(Child(op, "ProposedMaxPduSize")));
                Set(o, "conformance", () => ConformanceValue(Child(op, "ProposedConformance")));
                break;
            case "initiate-response":
                Set(o, "dlms_version", () => Int(Child(op, "NegotiatedDlmsVersionNumber")));
                Set(o, "max_receive_pdu_size", () => Int(Child(op, "NegotiatedMaxPduSize")));
                Set(o, "vaa_name", () => Int(Child(op, "VaaName")));
                Set(o, "conformance", () => ConformanceValue(Child(op, "NegotiatedConformance")));
                break;
            case "rlrq":
                if (Child(op, "Reason") != null)
                {
                    Set(o, "reason", () => (int)TranslatorSimpleTags.ValueOfReleaseRequestReason(Val(Child(op, "Reason"))));
                }
                break;
            case "rlre":
                if (Child(op, "Reason") != null)
                {
                    Set(o, "reason", () => (int)TranslatorSimpleTags.ValueOfReleaseResponseReason(Val(Child(op, "Reason"))));
                }
                break;
        }
    }

    // Translator names -> the Green Book context-id and mechanism-id.
    static readonly Dictionary<string, int> Contexts = new Dictionary<string, int>
    {
        ["LN"] = 1, ["SN"] = 2, ["LN_WITH_CIPHERING"] = 3, ["SN_WITH_CIPHERING"] = 4,
    };

    static readonly Dictionary<string, int> Mechanisms = new Dictionary<string, int>
    {
        ["None"] = 0, ["Low"] = 1, ["High"] = 2, ["HighMD5"] = 3, ["HighSHA1"] = 4,
        ["HighGMAC"] = 5, ["HighSHA256"] = 6, ["HighECDSA"] = 7,
    };

    static int ErrorCodeValue(XElement e)
    {
        if (e == null || Val(e) == null)
        {
            throw new NotMappedException("no result");
        }
        return (int)TranslatorSimpleTags.ValueOfErrorCode(Val(e));
    }

    static ExceptionStateError StateErrorValue(string name)
    {
        foreach (ExceptionStateError v in Enum.GetValues(typeof(ExceptionStateError)))
        {
            if (TranslatorSimpleTags.StateErrorToString(v) == name)
            {
                return v;
            }
        }
        throw new NotMappedException("state error " + name);
    }

    // Gurux's Conformance enum gives BIT STRING bit n the flag 1 << n
    // (ReservedZero, bit 0, is 0x1); pydlms keeps the three octets as a
    // big-endian integer, where bit 0 (first octet's MSB) is 0x800000. Same
    // bits, opposite numbering: map 1 << n to 1 << (23 - n).
    static long ConformanceValue(XElement e)
    {
        long gurux = 0;
        foreach (XElement bit in Elements(e))
        {
            gurux |= (long)(Conformance)Enum.Parse(typeof(Conformance), (string)bit.Attribute("Name"));
        }
        long value = 0;
        for (int n = 0; n != 24; ++n)
        {
            if ((gurux & (1L << n)) != 0)
            {
                value |= 1L << (23 - n);
            }
        }
        return value;
    }

    static JsonObject Descriptor(XElement x, string idTag, string idName)
    {
        byte[] ln = Hex(Val(Child(x, "InstanceId")));
        return new JsonObject
        {
            ["class_id"] = Int(Child(x, "ClassId")),
            ["instance_id"] = string.Join(".", ln.Select(b => b.ToString())),
            [idName] = Int(Child(x, idTag)),
        };
    }

    // One Get-Data-Result: <Data>tree</Data> or <DataAccessError Value=name/>.
    static JsonObject DataResult(XElement e)
    {
        if (e.Name.LocalName == "Data")
        {
            return new JsonObject { ["data"] = DataNode(Elements(e).Single()) };
        }
        if (e.Name.LocalName == "DataAccessError")
        {
            return new JsonObject { ["error"] = ErrorCodeValue(e) };
        }
        throw new NotMappedException("result element " + e.Name.LocalName);
    }

    // ---------------------------------------------------------------- push

    // Gurux insists on an authentication key even for security 0x20
    // (encryption only), where AES-GCM does not use it (Green Book 9.2.7.2.4.1:
    // A is SC || AK only when authentication is applied). A zero key stands in
    // for a missing one; it cannot change a 0x20 result, and with 0x10/0x30 it
    // makes the tag check fail, i.e. a rejection.
    const string NoKey = "00000000000000000000000000000000";

    static JsonNode OpPush(string hex, string ek, string ak)
    {
        byte[] apdu = Hex(hex);
        // "-" marks an absent key (PROTOCOL.md).
        ek = ek == "-" ? null : ek;
        ak = ak == "-" ? null : ak;
        bool ciphered = apdu.Length > 0 && apdu[0] != (byte)Command.DataNotification;
        if (ciphered && string.IsNullOrEmpty(ak))
        {
            ak = NoKey;
        }
        // The client path: what a Gurux client application runs on a push.
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.PDU);
        if (!string.IsNullOrEmpty(ek))
        {
            client.Ciphering.BlockCipherKey = Hex(ek);
            client.Ciphering.AuthenticationKey = Hex(ak);
            client.Ciphering.Security = Security.AuthenticationEncryption;
            client.Ciphering.SecuritySuite = SuiteOf(apdu);
        }
        var reply = new GXReplyData();
        var notify = new GXReplyData();
        client.GetData(new GXByteBuffer(apdu), reply, notify);
        GXReplyData got = notify.Command == Command.DataNotification ? notify : reply;
        if (got.Command != Command.DataNotification)
        {
            throw new RejectException("not a DataNotification: " + got.Command);
        }
        // The tree: decipher with GXSecure (the translator's own ciphered
        // output mixes "#" comments into the XML), then PduToXml.
        byte[] plain = ciphered ? Decrypt(ek ?? NoKey, ak, null, apdu) : apdu;
        XElement root = ParseXml(Translator(null, null).PduToXml(plain));
        XElement dn = Elements(root).SingleOrDefault(e => e.Name.LocalName == "DataNotification");
        if (dn == null)
        {
            throw new RejectException("translator found no DataNotification");
        }
        var o = new JsonObject();
        Fields("data-notification", dn, o);
        return o;
    }

    // ------------------------------------------------------------- decrypt

    // GXSecure.DecryptAesGcm refuses an APDU whose security-control suite
    // (low bits) differs from the configured one (DecipheringError), so
    // configure the suite the APDU announces, as a user who knows the meter
    // would. glo-/ded-: tag, length, SC; general-glo/-ded: tag, title, length, SC.
    static SecuritySuite SuiteOf(byte[] apdu)
    {
        int pos = 1;
        if (apdu[0] == (byte)Command.GeneralGloCiphering || apdu[0] == (byte)Command.GeneralDedCiphering)
        {
            pos += 1 + apdu[1];
        }
        else if (apdu[0] == (byte)Command.GeneralCiphering || apdu[0] == (byte)Command.GeneralSigning)
        {
            return SecuritySuite.Suite0;
        }
        pos += (apdu[pos] & 0x80) != 0 ? 1 + (apdu[pos] & 0x7F) : 1;
        return pos < apdu.Length ? (SecuritySuite)(apdu[pos] & 0x03) : SecuritySuite.Suite0;
    }

    static byte[] Decrypt(string ek, string ak, string title, byte[] apdu)
    {
        if (string.IsNullOrEmpty(ak) || ak == "-")
        {
            ak = NoKey;
        }
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.PDU);
        client.Ciphering.BlockCipherKey = Hex(ek);
        // The encryption key also opens broadcast-key APDUs (PROTOCOL.md):
        // GXSecure.DecryptAesGcm takes Cipher.BroadcastBlockCipherKey for SC bit 6.
        client.Ciphering.BroadcastBlockCipherKey = Hex(ek);
        client.Ciphering.AuthenticationKey = Hex(ak);
        client.Ciphering.SecuritySuite = SuiteOf(apdu);
        var p = new AesGcmParameter(client.Settings, string.IsNullOrEmpty(title) ? null : Hex(title),
            Hex(ek), Hex(ak));
        return GXSecure.DecryptAesGcm(p, new GXByteBuffer(apdu));
    }
}
