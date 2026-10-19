// pydlms interop oracle for OpenMUC jDLMS (tests/interop/PROTOCOL.md).
//
// Every decode below is jDLMS code: Data / COSEMpdu (A-XDR), ACSEApdu (BER,
// asn1bean), DataConverter (Data -> DataObject) and GcmModule (AES-GCM).
// This file only maps the resulting objects onto the protocol's JSON model.

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.beanit.asn1bean.ber.types.BerInteger;
import com.beanit.asn1bean.ber.types.BerObjectIdentifier;
import com.beanit.asn1bean.ber.types.BerOctetString;
import com.beanit.asn1bean.ber.ReverseByteArrayOutputStream;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import org.openmuc.jdlms.SecuritySuite;
import org.openmuc.jdlms.SecuritySuite.EncryptionMechanism;
import org.openmuc.jdlms.SecuritySuite.SecurityPolicy;
import org.openmuc.jdlms.AuthenticationMechanism;
import org.openmuc.jdlms.datatypes.BitString;
import org.openmuc.jdlms.datatypes.CompactArray;
import org.openmuc.jdlms.datatypes.CosemDate;
import org.openmuc.jdlms.datatypes.CosemDateFormat;
import org.openmuc.jdlms.datatypes.CosemDateTime;
import org.openmuc.jdlms.datatypes.CosemTime;
import org.openmuc.jdlms.datatypes.DataObject;
import org.openmuc.jdlms.internal.DataConverter;
import org.openmuc.jdlms.internal.asn1.axdr.types.AxdrOctetString;
import org.openmuc.jdlms.internal.asn1.axdr.types.AxdrOptional;
import org.openmuc.jdlms.internal.asn1.cosem.*;
import org.openmuc.jdlms.internal.asn1.iso.acse.AARQApdu;
import org.openmuc.jdlms.internal.asn1.iso.acse.AAREApdu;
import org.openmuc.jdlms.internal.asn1.iso.acse.ACSEApdu;
import org.openmuc.jdlms.internal.asn1.iso.acse.APTitle;
import org.openmuc.jdlms.internal.asn1.iso.acse.AssociateSourceDiagnostic;
import org.openmuc.jdlms.internal.asn1.iso.acse.AuthenticationValue;
import org.openmuc.jdlms.internal.security.crypto.GcmModule;

public final class Oracle {

    static final class Unsupported extends RuntimeException {
        Unsupported(String msg) {
            super(msg);
        }
    }

    public static void run() throws IOException {
        PrintStream out = new PrintStream(System.out, true, "UTF-8");
        System.setOut(System.err); // nothing but replies on stdout
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.trim().isEmpty()) {
                continue;
            }
            out.println(answer(line.trim()).toString());
            out.flush();
        }
    }

    static JsonObject answer(String line) {
        int sp = line.indexOf(' ');
        String op = sp < 0 ? line : line.substring(0, sp);
        String rest = sp < 0 ? "" : line.substring(sp + 1).trim();
        String[] args = rest.isEmpty() ? new String[0] : rest.split("\\s+");
        JsonObject reply = new JsonObject();
        try {
            JsonElement result;
            switch (op) {
            case "hello":
                reply.addProperty("ok", true);
                reply.addProperty("library", "jdlms");
                reply.addProperty("version", Main.JDLMS_VERSION);
                JsonArray ops = new JsonArray();
                for (String o : new String[] { "data", "encode-data", "apdu", "push", "decrypt" }) {
                    ops.add(o);
                }
                reply.add("ops", ops);
                return reply;
            case "data":
                result = opData(hex(args[0]));
                break;
            case "encode-data":
                result = opEncodeData(JsonParser.parseString(rest).getAsJsonObject());
                break;
            case "apdu":
                result = opApdu(hex(args[0]));
                break;
            case "push":
                result = opPush(hex(args[0]), args.length > 1 ? key(args[1]) : null,
                        args.length > 2 ? key(args[2]) : null);
                break;
            case "decrypt":
                JsonObject p = new JsonObject();
                p.addProperty("plaintext", toHex(decrypt(key(args[0]), key(args[1]), key(args[2]), hex(args[3]))));
                result = p;
                break;
            default:
                throw new Unsupported("unknown op " + op);
            }
            reply.addProperty("ok", true);
            reply.add("result", result);
        } catch (Unsupported e) {
            reply = new JsonObject();
            reply.addProperty("ok", false);
            reply.addProperty("unsupported", true);
            reply.addProperty("error", e.getMessage());
        } catch (Throwable e) { // jDLMS throws IOException, runtime and array errors alike
            reply = new JsonObject();
            reply.addProperty("ok", false);
            reply.addProperty("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return reply;
    }

    // ---------------------------------------------------------------- data

    static JsonElement opData(byte[] raw) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        Data d = new Data();
        d.decode(in);
        if (in.available() > 0) {
            throw new IOException(in.available() + " trailing octets");
        }
        return dataJson(d);
    }

    /** Raw A-XDR Data through jDLMS's own converter to its public DataObject. */
    static JsonObject dataJson(Data d) {
        if (d.getChoiceIndex() == Data.Choices.DONT_CARE) {
            // DataConverter folds dont-care into null-data; keep the tag visible.
            JsonObject o = new JsonObject();
            o.addProperty("t", "dont-care");
            o.add("v", JsonNull.INSTANCE);
            return o;
        }
        return objJson(DataConverter.convertDataToDataObject(d));
    }

    static String typeName(DataObject.Type t) {
        switch (t) {
        case NULL_DATA:
            return "null-data";
        case BOOLEAN:
            return "boolean";
        case LONG_INTEGER:
            return "long";
        case ENUMERATE:
            return "enum";
        default:
            return t.name().toLowerCase().replace('_', '-');
        }
    }

    static String typeName(CompactArray.TypeDesc.Type t) {
        switch (t) {
        case NULL_DATA:
            return "null-data";
        case BOOL:
            return "boolean";
        case LONG_INTEGER:
            return "long";
        case ENUMERATE:
            return "enum";
        default:
            return t.name().toLowerCase().replace('_', '-');
        }
    }

    static JsonObject objJson(DataObject o) {
        JsonObject j = new JsonObject();
        DataObject.Type t = o.getType();
        j.addProperty("t", typeName(t));
        switch (t) {
        case NULL_DATA:
            j.add("v", JsonNull.INSTANCE);
            break;
        case ARRAY:
        case STRUCTURE: {
            JsonArray a = new JsonArray();
            List<DataObject> items = o.getValue();
            for (DataObject i : items) {
                a.add(objJson(i));
            }
            j.add("v", a);
            break;
        }
        case BOOLEAN:
            j.addProperty("v", (Boolean) o.getValue());
            break;
        case BIT_STRING: {
            BitString b = o.getValue();
            StringBuilder s = new StringBuilder();
            byte[] bytes = b.getBitString();
            for (int i = 0; i < b.getNumBits(); i++) {
                s.append(((bytes[i / 8] >> (7 - i % 8)) & 1) == 1 ? '1' : '0');
            }
            j.addProperty("v", s.toString());
            break;
        }
        case OCTET_STRING:
            j.addProperty("v", toHex((byte[]) o.getValue()));
            break;
        case VISIBLE_STRING:
            j.addProperty("v", new String((byte[]) o.getValue(), StandardCharsets.ISO_8859_1));
            break;
        case UTF8_STRING:
            j.addProperty("v", new String((byte[]) o.getValue(), StandardCharsets.UTF_8));
            break;
        case FLOAT32:
            j.addProperty("v", String.format("%08x", Float.floatToRawIntBits((Float) o.getValue())));
            break;
        case FLOAT64:
            j.addProperty("v", String.format("%016x", Double.doubleToRawLongBits((Double) o.getValue())));
            break;
        case DATE_TIME:
        case DATE:
        case TIME:
            j.addProperty("v", toHex(((CosemDateFormat) o.getValue()).encode()));
            break;
        case COMPACT_ARRAY: {
            // jDLMS keeps array-contents as raw octets and never decodes the
            // items, so only the type description is reported.
            CompactArray c = o.getValue();
            JsonObject v = new JsonObject();
            v.add("description", descJson(c.getTypeDescription()));
            j.add("v", v);
            break;
        }
        default: // every number type
            j.addProperty("v", (Number) o.getValue());
        }
        return j;
    }

    static JsonObject descJson(CompactArray.TypeDesc d) {
        JsonObject j = new JsonObject();
        j.addProperty("t", typeName(d.getType()));
        if (d.getType() == CompactArray.TypeDesc.Type.STRUCTURE) {
            JsonArray m = new JsonArray();
            List<CompactArray.TypeDesc> members = d.getValue();
            for (CompactArray.TypeDesc x : members) {
                m.add(descJson(x));
            }
            j.add("members", m);
        }
        else if (d.getType() == CompactArray.TypeDesc.Type.ARRAY) {
            CompactArray.DescriptionArray a = d.getValue();
            j.addProperty("count", a.getNumOfeElements());
            j.add("of", descJson(a.getTypeDescription()));
        }
        return j;
    }

    // --------------------------------------------------------- encode-data

    static JsonElement opEncodeData(JsonObject tree) throws IOException {
        Data d = DataConverter.convertDataObjectToData(jsonObj(tree));
        ReverseByteArrayOutputStream os = new ReverseByteArrayOutputStream(1024, true);
        d.encode(os);
        JsonObject r = new JsonObject();
        r.addProperty("hex", toHex(os.getArray()));
        return r;
    }

    /** JSON tree -> jDLMS public DataObject via its factory methods. */
    static DataObject jsonObj(JsonObject j) {
        String t = j.get("t").getAsString();
        JsonElement v = j.get("v");
        switch (t) {
        case "null-data":
            return DataObject.newNullData();
        case "array":
        case "structure": {
            List<DataObject> items = new ArrayList<>();
            for (JsonElement e : v.getAsJsonArray()) {
                items.add(jsonObj(e.getAsJsonObject()));
            }
            return t.equals("array") ? DataObject.newArrayData(items) : DataObject.newStructureData(items);
        }
        case "boolean":
            return DataObject.newBoolData(v.getAsBoolean());
        case "bit-string": {
            String bits = v.getAsString();
            byte[] b = new byte[(bits.length() + 7) / 8];
            for (int i = 0; i < bits.length(); i++) {
                if (bits.charAt(i) == '1') {
                    b[i / 8] |= (byte) (0x80 >> (i % 8));
                }
            }
            return DataObject.newBitStringData(new BitString(b, bits.length()));
        }
        case "double-long":
            return DataObject.newInteger32Data(v.getAsInt());
        case "double-long-unsigned":
            return DataObject.newUInteger32Data(v.getAsLong());
        case "octet-string":
            return DataObject.newOctetStringData(hex(v.getAsString()));
        case "visible-string":
            return DataObject.newVisibleStringData(v.getAsString().getBytes(StandardCharsets.ISO_8859_1));
        case "utf8-string":
            return DataObject.newUtf8StringData(v.getAsString().getBytes(StandardCharsets.UTF_8));
        case "bcd":
            return DataObject.newBcdData(v.getAsBigInteger().byteValueExact());
        case "integer":
            return DataObject.newInteger8Data(v.getAsBigInteger().byteValueExact());
        case "long":
            return DataObject.newInteger16Data(v.getAsBigInteger().shortValueExact());
        case "unsigned":
            return DataObject.newUInteger8Data(v.getAsBigInteger().shortValueExact());
        case "long-unsigned":
            return DataObject.newUInteger16Data(v.getAsBigInteger().intValueExact());
        case "long64":
            return DataObject.newInteger64Data(v.getAsBigInteger().longValueExact());
        case "long64-unsigned":
            // Java long: values >= 2^63 raise ArithmeticException here, as
            // DataObject cannot hold them anyway.
            return DataObject.newUInteger64Data(v.getAsBigInteger().longValueExact());
        case "enum":
            return DataObject.newEnumerateData(v.getAsInt());
        case "float32":
            return DataObject.newFloat32Data(Float.intBitsToFloat((int) Long.parseLong(v.getAsString(), 16)));
        case "float64":
            return DataObject
                    .newFloat64Data(Double.longBitsToDouble(new BigInteger(v.getAsString(), 16).longValue()));
        case "date-time":
            return DataObject.newDateTimeData(CosemDateTime.decode(hex(v.getAsString())));
        case "date":
            return DataObject.newDateData(CosemDate.decode(hex(v.getAsString())));
        case "time":
            return DataObject.newTimeData(CosemTime.decode(hex(v.getAsString())));
        case "compact-array":
            throw new Unsupported("jDLMS CompactArray takes pre-encoded array-contents; no item encoder");
        default:
            throw new Unsupported("type " + t);
        }
    }

    // ---------------------------------------------------------------- apdu

    static JsonElement opApdu(byte[] raw) throws IOException {
        int tag = raw[0] & 0xff;
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        JsonObject r;
        if (tag >= 0x60 && tag <= 0x63) {
            ACSEApdu a = new ACSEApdu();
            a.decode(in, null);
            r = acseJson(a);
        }
        else {
            COSEMpdu p = new COSEMpdu();
            p.decode(in);
            r = cosemJson(p);
        }
        if (in.available() > 0) {
            throw new IOException(in.available() + " trailing octets");
        }
        return r;
    }

    static int lastArc(BerObjectIdentifier oid) {
        int[] v = oid.value;
        return v[v.length - 1];
    }

    static JsonElement octets(BerOctetString s) {
        return s == null ? JsonNull.INSTANCE : new JsonPrimitive(toHex(s.value));
    }

    static JsonElement apTitle(APTitle t) {
        return t == null ? JsonNull.INSTANCE : octets(t.getApTitleForm2());
    }

    static JsonElement authValue(AuthenticationValue v) {
        if (v == null) {
            return JsonNull.INSTANCE;
        }
        if (v.getCharstring() != null) {
            return octets(v.getCharstring());
        }
        throw new Unsupported("bitstring authentication-value");
    }

    static String userInfo(BerOctetString s) {
        return s == null ? "" : toHex(s.value);
    }

    static JsonObject acseJson(ACSEApdu a) {
        JsonObject j = new JsonObject();
        if (a.getAarq() != null) {
            AARQApdu q = a.getAarq();
            j.addProperty("kind", "aarq");
            j.addProperty("application_context", lastArc(q.getApplicationContextName()));
            j.add("mechanism", q.getMechanismName() == null ? JsonNull.INSTANCE
                    : new JsonPrimitive(lastArc(q.getMechanismName())));
            j.add("calling_authentication_value", authValue(q.getCallingAuthenticationValue()));
            j.add("calling_ap_title", apTitle(q.getCallingAPTitle()));
            j.add("calling_ae_qualifier", q.getCallingAEQualifier() == null ? JsonNull.INSTANCE
                    : octets(q.getCallingAEQualifier().getAeQualifierForm2()));
            j.addProperty("user_information", userInfo(q.getUserInformation()));
        }
        else if (a.getAare() != null) {
            AAREApdu e = a.getAare();
            j.addProperty("kind", "aare");
            j.addProperty("application_context", lastArc(e.getApplicationContextName()));
            j.addProperty("result", e.getResult().value);
            AssociateSourceDiagnostic d = e.getResultSourceDiagnostic();
            if (d.getAcseServiceUser() != null) {
                j.addProperty("diagnostic_source", 1);
                j.addProperty("diagnostic", d.getAcseServiceUser().value);
            }
            else {
                j.addProperty("diagnostic_source", 2);
                j.addProperty("diagnostic", d.getAcseServiceProvider().value);
            }
            j.add("responding_ap_title", apTitle(e.getRespondingAPTitle()));
            j.add("mechanism", e.getMechanismName() == null ? JsonNull.INSTANCE
                    : new JsonPrimitive(lastArc(e.getMechanismName())));
            j.add("responding_authentication_value", authValue(e.getRespondingAuthenticationValue()));
            j.addProperty("user_information", userInfo(e.getUserInformation()));
        }
        else if (a.getRlrq() != null) {
            j.addProperty("kind", "rlrq");
            BerInteger reason = a.getRlrq().getReason();
            j.add("reason", reason == null ? JsonNull.INSTANCE : new JsonPrimitive(reason.value));
            j.addProperty("user_information", userInfo(a.getRlrq().getUserInformation()));
        }
        else {
            j.addProperty("kind", "rlre");
            BerInteger reason = a.getRlre().getReason();
            j.add("reason", reason == null ? JsonNull.INSTANCE : new JsonPrimitive(reason.value));
            j.addProperty("user_information", userInfo(a.getRlre().getUserInformation()));
        }
        return j;
    }

    static int invokeId(InvokeIdAndPriority p) {
        return p.getValue()[0] & 0xff;
    }

    static String obis(AxdrOctetString s) {
        byte[] b = s.getValue();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            sb.append(i == 0 ? "" : ".").append(b[i] & 0xff);
        }
        return sb.toString();
    }

    static JsonObject attr(CosemAttributeDescriptor d) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", "attribute-descriptor");
        j.addProperty("class_id", d.classId.getValue());
        j.addProperty("instance_id", obis(d.instanceId));
        j.addProperty("attribute_id", d.attributeId.getValue());
        return j;
    }

    static JsonObject method(CosemMethodDescriptor d) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", "method-descriptor");
        j.addProperty("class_id", d.classId.getValue());
        j.addProperty("instance_id", obis(d.instanceId));
        j.addProperty("method_id", d.methodId.getValue());
        return j;
    }

    static JsonElement access(AxdrOptional<SelectiveAccessDescriptor> o) {
        if (!o.isUsed()) {
            return JsonNull.INSTANCE;
        }
        SelectiveAccessDescriptor s = o.getValue();
        JsonObject j = new JsonObject();
        j.addProperty("kind", "selective-access");
        j.addProperty("selector", s.accessSelector.getValue());
        j.add("parameters", dataJson(s.accessParameters));
        return j;
    }

    static JsonObject selection(SelectiveAccessDescriptor s) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", "selective-access");
        j.addProperty("selector", s.accessSelector.getValue());
        j.add("parameters", dataJson(s.accessParameters));
        return j;
    }

    static JsonArray dataList(List<Data> list) {
        JsonArray a = new JsonArray();
        for (Data d : list) {
            a.add(dataJson(d));
        }
        return a;
    }

    static JsonArray accessSpecs(List<AccessRequestSpecification> list) {
        JsonArray a = new JsonArray();
        for (AccessRequestSpecification s : list) {
            JsonObject o = new JsonObject();
            switch (s.getChoiceIndex()) {
            case ACCESS_REQUEST_GET:
                o.addProperty("kind", "access-request-get");
                o.add("attribute", attr(s.accessRequestGet.cosemAttributeDescriptor));
                break;
            case ACCESS_REQUEST_SET:
                o.addProperty("kind", "access-request-set");
                o.add("attribute", attr(s.accessRequestSet.cosemAttributeDescriptor));
                break;
            case ACCESS_REQUEST_ACTION:
                o.addProperty("kind", "access-request-action");
                o.add("method", method(s.accessRequestAction.cosemMethodDescriptor));
                break;
            case ACCESS_REQUEST_GET_WITH_SELECTION:
                o.addProperty("kind", "access-request-get-with-selection");
                o.add("attribute", attr(s.accessRequestGetWithSelection.cosemAttributeDescriptor));
                o.add("access", selection(s.accessRequestGetWithSelection.accessSelection));
                break;
            case ACCESS_REQUEST_SET_WITH_SELECTION:
                o.addProperty("kind", "access-request-set-with-selection");
                o.add("attribute", attr(s.accessRequestSetWithSelection.cosemAttributeDescriptor));
                o.add("access", selection(s.accessRequestSetWithSelection.accessSelection));
                break;
            default:
                throw new Unsupported("access-request-specification " + s.getChoiceIndex());
            }
            a.add(o);
        }
        return a;
    }

    static JsonObject getDataResult(GetDataResult r) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", "get-data-result");
        if (r.getChoiceIndex() == GetDataResult.Choices.DATA) {
            j.add("data", dataJson(r.data));
            j.add("error", JsonNull.INSTANCE);
        }
        else {
            j.add("data", JsonNull.INSTANCE);
            j.addProperty("error", r.dataAccessResult.getValue());
        }
        return j;
    }

    static JsonObject start(String kind, InvokeIdAndPriority p) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", kind);
        j.addProperty("invoke_id", invokeId(p));
        return j;
    }

    static void block(JsonObject j, DataBlockSA b) {
        j.addProperty("last_block", b.lastBlock.getValue());
        j.addProperty("block_number", b.blockNumber.getValue());
        j.addProperty("raw_data", toHex(b.rawData.getValue()));
    }

    static JsonObject cosemJson(COSEMpdu p) {
        JsonObject j;
        switch (p.getChoiceIndex()) {
        case GET_REQUEST: {
            GetRequest g = p.getRequest;
            switch (g.getChoiceIndex()) {
            case GET_REQUEST_NORMAL:
                j = start("get-request-normal", g.getRequestNormal.invokeIdAndPriority);
                j.add("attribute", attr(g.getRequestNormal.cosemAttributeDescriptor));
                j.add("access", access(g.getRequestNormal.accessSelection));
                return j;
            case GET_REQUEST_NEXT:
                j = start("get-request-next", g.getRequestNext.invokeIdAndPriority);
                j.addProperty("block_number", g.getRequestNext.blockNumber.getValue());
                return j;
            default:
                j = start("get-request-with-list", g.getRequestWithList.invokeIdAndPriority);
                j.add("items", attrList(g.getRequestWithList.attributeDescriptorList.list(), null));
                return j;
            }
        }
        case GET_RESPONSE: {
            GetResponse g = p.getResponse;
            switch (g.getChoiceIndex()) {
            case GET_RESPONSE_NORMAL:
                j = start("get-response-normal", g.getResponseNormal.invokeIdAndPriority);
                j.add("result", getDataResult(g.getResponseNormal.result));
                return j;
            case GET_RESPONSE_WITH_DATABLOCK: {
                DataBlockG b = g.getResponseWithDatablock.result;
                j = start("get-response-with-datablock", g.getResponseWithDatablock.invokeIdAndPriority);
                j.addProperty("last_block", b.lastBlock.getValue());
                j.addProperty("block_number", b.blockNumber.getValue());
                if (b.result.getChoiceIndex() == DataBlockG.SubChoiceResult.Choices.RAW_DATA) {
                    j.addProperty("raw_data", toHex(b.result.rawData.getValue()));
                    j.add("error", JsonNull.INSTANCE);
                }
                else {
                    j.add("raw_data", JsonNull.INSTANCE);
                    j.addProperty("error", b.result.dataAccessResult.getValue());
                }
                return j;
            }
            default: {
                j = start("get-response-with-list", g.getResponseWithList.invokeIdAndPriority);
                JsonArray a = new JsonArray();
                for (GetDataResult r : g.getResponseWithList.result.list()) {
                    a.add(getDataResult(r));
                }
                j.add("results", a);
                return j;
            }
            }
        }
        case SET_REQUEST: {
            SetRequest s = p.setRequest;
            switch (s.getChoiceIndex()) {
            case SET_REQUEST_NORMAL:
                j = start("set-request-normal", s.setRequestNormal.invokeIdAndPriority);
                j.add("attribute", attr(s.setRequestNormal.cosemAttributeDescriptor));
                j.add("access", access(s.setRequestNormal.accessSelection));
                j.add("value", dataJson(s.setRequestNormal.value));
                return j;
            case SET_REQUEST_WITH_FIRST_DATABLOCK:
                j = start("set-request-with-first-datablock", s.setRequestWithFirstDatablock.invokeIdAndPriority);
                j.add("attribute", attr(s.setRequestWithFirstDatablock.cosemAttributeDescriptor));
                j.add("access", access(s.setRequestWithFirstDatablock.accessSelection));
                block(j, s.setRequestWithFirstDatablock.datablock);
                return j;
            case SET_REQUEST_WITH_DATABLOCK:
                j = start("set-request-with-datablock", s.setRequestWithDatablock.invokeIdAndPriority);
                block(j, s.setRequestWithDatablock.datablock);
                return j;
            case SET_REQUEST_WITH_LIST:
                j = start("set-request-with-list", s.setRequestWithList.invokeIdAndPriority);
                j.add("items", attrList(s.setRequestWithList.attributeDescriptorList.list(),
                        s.setRequestWithList.valueList.list()));
                return j;
            default:
                j = start("set-request-with-list-and-first-datablock",
                        s.setRequestWithListAndFirstDatablock.invokeIdAndPriority);
                j.add("items", attrList(s.setRequestWithListAndFirstDatablock.attributeDescriptorList.list(), null));
                block(j, s.setRequestWithListAndFirstDatablock.datablock);
                return j;
            }
        }
        case SET_RESPONSE: {
            SetResponse s = p.setResponse;
            switch (s.getChoiceIndex()) {
            case SET_RESPONSE_NORMAL:
                j = start("set-response-normal", s.setResponseNormal.invokeIdAndPriority);
                j.addProperty("result", s.setResponseNormal.result.getValue());
                return j;
            case SET_RESPONSE_DATABLOCK:
                j = start("set-response-datablock", s.setResponseDatablock.invokeIdAndPriority);
                j.addProperty("block_number", s.setResponseDatablock.blockNumber.getValue());
                return j;
            case SET_RESPONSE_LAST_DATABLOCK:
                j = start("set-response-last-datablock", s.setResponseLastDatablock.invokeIdAndPriority);
                j.addProperty("result", s.setResponseLastDatablock.result.getValue());
                j.addProperty("block_number", s.setResponseLastDatablock.blockNumber.getValue());
                return j;
            case SET_RESPONSE_WITH_LIST: {
                j = start("set-response-with-list", s.setResponseWithList.invokeIdAndPriority);
                JsonArray a = new JsonArray();
                for (org.openmuc.jdlms.internal.asn1.axdr.types.AxdrEnum e : s.setResponseWithList.result.list()) {
                    a.add(e.getValue());
                }
                j.add("results", a);
                return j;
            }
            default: {
                j = start("set-response-last-datablock-with-list",
                        s.setResponseLastDatablockWithList.invokeIdAndPriority);
                JsonArray a = new JsonArray();
                for (org.openmuc.jdlms.internal.asn1.axdr.types.AxdrEnum e : s.setResponseLastDatablockWithList.result
                        .list()) {
                    a.add(e.getValue());
                }
                j.add("results", a);
                j.addProperty("block_number", s.setResponseLastDatablockWithList.blockNumber.getValue());
                return j;
            }
            }
        }
        case ACTION_REQUEST: {
            ActionRequest a = p.actionRequest;
            switch (a.getChoiceIndex()) {
            case ACTION_REQUEST_NORMAL:
                j = start("action-request-normal", a.actionRequestNormal.invokeIdAndPriority);
                j.add("method", method(a.actionRequestNormal.cosemMethodDescriptor));
                j.add("parameters", a.actionRequestNormal.methodInvocationParameters.isUsed()
                        ? dataJson(a.actionRequestNormal.methodInvocationParameters.getValue())
                        : JsonNull.INSTANCE);
                return j;
            case ACTION_REQUEST_NEXT_PBLOCK:
                j = start("action-request-next-pblock", a.actionRequestNextPblock.invokeIdAndPriority);
                j.addProperty("block_number", a.actionRequestNextPblock.blockNumber.getValue());
                return j;
            case ACTION_REQUEST_WITH_LIST: {
                j = start("action-request-with-list", a.actionRequestWithList.invokeIdAndPriority);
                List<CosemMethodDescriptor> ms = a.actionRequestWithList.cosemMethodDescriptorList.list();
                List<Data> ps = a.actionRequestWithList.methodInvocationParameters.list();
                JsonArray items = new JsonArray();
                for (int i = 0; i < ms.size(); i++) {
                    JsonArray pair = new JsonArray();
                    pair.add(method(ms.get(i)));
                    pair.add(i < ps.size() ? dataJson(ps.get(i)) : JsonNull.INSTANCE);
                    items.add(pair);
                }
                j.add("items", items);
                return j;
            }
            case ACTION_REQUEST_WITH_FIRST_PBLOCK:
                j = start("action-request-with-first-pblock", a.actionRequestWithFirstPblock.invokeIdAndPriority);
                j.add("method", method(a.actionRequestWithFirstPblock.cosemMethodDescriptor));
                block(j, a.actionRequestWithFirstPblock.pblock);
                return j;
            case ACTION_REQUEST_WITH_PBLOCK:
                j = start("action-request-with-pblock", a.actionRequestWithPblock.invokeIdAndPriority);
                block(j, a.actionRequestWithPblock.pblock);
                return j;
            default: {
                j = start("action-request-with-list-and-first-pblock",
                        a.actionRequestWithListAndFirstPblock.invokeIdAndPriority);
                JsonArray ms = new JsonArray();
                for (CosemMethodDescriptor m : a.actionRequestWithListAndFirstPblock.cosemMethodDescriptorList.list()) {
                    ms.add(method(m));
                }
                j.add("methods", ms);
                block(j, a.actionRequestWithListAndFirstPblock.pblock);
                return j;
            }
            }
        }
        case ACTION_RESPONSE: {
            ActionResponse a = p.actionResponse;
            switch (a.getChoiceIndex()) {
            case ACTION_RESPONSE_NORMAL: {
                j = start("action-response-normal", a.actionResponseNormal.invokeIdAndPriority);
                ActionResponseWithOptionalData r = a.actionResponseNormal.singleResponse;
                j.addProperty("result", r.result.getValue());
                j.add("return_data",
                        r.returnParameters.isUsed() ? getDataResult(r.returnParameters.getValue()) : JsonNull.INSTANCE);
                return j;
            }
            case ACTION_RESPONSE_WITH_PBLOCK:
                j = start("action-response-with-pblock", a.actionResponseWithPblock.invokeIdAndPriority);
                block(j, a.actionResponseWithPblock.pblock);
                return j;
            case ACTION_RESPONSE_WITH_LIST: {
                j = start("action-response-with-list", a.actionResponseWithList.invokeIdAndPriority);
                JsonArray rs = new JsonArray();
                for (ActionResponseWithOptionalData r : a.actionResponseWithList.listOfResponses.list()) {
                    JsonArray pair = new JsonArray();
                    pair.add(r.result.getValue());
                    pair.add(r.returnParameters.isUsed() ? getDataResult(r.returnParameters.getValue())
                            : JsonNull.INSTANCE);
                    rs.add(pair);
                }
                j.add("results", rs);
                return j;
            }
            default:
                j = start("action-response-next-pblock", a.actionResponseNextPblock.invokeIdAndPriority);
                j.addProperty("block_number", a.actionResponseNextPblock.blockNumber.getValue());
                return j;
            }
        }
        case ACCESS_REQUEST: {
            AccessRequest q = p.accessRequest;
            j = new JsonObject();
            j.addProperty("kind", "access-request");
            j.addProperty("long_invoke_id", q.longInvokeIdAndPriority.getValue());
            byte[] qdt = q.dateTime.getValue();
            j.add("date_time", qdt.length == 0 ? JsonNull.INSTANCE : new JsonPrimitive(toHex(qdt)));
            j.add("specifications", accessSpecs(q.accessRequestBody.accessRequestSpecification.list()));
            j.add("data", dataList(q.accessRequestBody.accessRequestListOfData.list()));
            return j;
        }
        case ACCESS_RESPONSE: {
            AccessResponse q = p.accessResponse;
            j = new JsonObject();
            j.addProperty("kind", "access-response");
            j.addProperty("long_invoke_id", q.longInvokeIdAndPriority.getValue());
            byte[] qdt = q.dateTime.getValue();
            j.add("date_time", qdt.length == 0 ? JsonNull.INSTANCE : new JsonPrimitive(toHex(qdt)));
            AccessResponseBody b = q.accessResponseBody;
            j.add("specifications", b.accessRequestSpecification.isUsed()
                    ? accessSpecs(b.accessRequestSpecification.getValue().list())
                    : JsonNull.INSTANCE);
            j.add("data", dataList(b.accessResponseListOfData.list()));
            JsonArray rs = new JsonArray();
            for (AccessResponseSpecification r : b.accessResponseSpecification.list()) {
                JsonObject o = new JsonObject();
                switch (r.getChoiceIndex()) {
                case ACCESS_RESPONSE_GET:
                    o.addProperty("kind", "access-response-get");
                    o.addProperty("result", r.accessResponseGet.result.getValue());
                    break;
                case ACCESS_RESPONSE_SET:
                    o.addProperty("kind", "access-response-set");
                    o.addProperty("result", r.accessResponseSet.result.getValue());
                    break;
                case ACCESS_RESPONSE_ACTION:
                    o.addProperty("kind", "access-response-action");
                    o.addProperty("result", r.accessResponseAction.result.getValue());
                    break;
                default:
                    throw new Unsupported("access-response-specification " + r.getChoiceIndex());
                }
                rs.add(o);
            }
            j.add("results", rs);
            return j;
        }
        case DATA_NOTIFICATION: {
            DataNotification n = p.dataNotification;
            j = new JsonObject();
            j.addProperty("kind", "data-notification");
            j.addProperty("long_invoke_id", n.longInvokeIdAndPriority.getValue());
            byte[] dt = n.dateTime.getValue();
            j.add("date_time", dt.length == 0 ? JsonNull.INSTANCE : new JsonPrimitive(toHex(dt)));
            j.add("body", dataJson(n.notificationBody.dataValue));
            return j;
        }
        case EVENT_NOTIFICATION_REQUEST: {
            EventNotificationRequest e = p.eventNotificationRequest;
            j = new JsonObject();
            j.addProperty("kind", "event-notification-request");
            j.add("time", e.time.isUsed() ? new JsonPrimitive(toHex(e.time.getValue().getValue())) : JsonNull.INSTANCE);
            j.add("attribute", attr(e.cosemAttributeDescriptor));
            j.add("value", dataJson(e.attributeValue));
            return j;
        }
        case EXCEPTION_RESPONSE: {
            j = new JsonObject();
            j.addProperty("kind", "exception-response");
            j.addProperty("state_error", p.exceptionResponse.stateError.getValue());
            j.addProperty("service_error", p.exceptionResponse.serviceError.getValue());
            return j;
        }
        case CONFIRMEDSERVICEERROR: {
            ConfirmedServiceError c = p.confirmedServiceError;
            j = new JsonObject();
            j.addProperty("kind", "confirmed-service-error");
            j.addProperty("service", c.getChoiceIndex().getValue());
            ServiceError s = serviceError(c);
            j.addProperty("error_type", s.getChoiceIndex().getValue());
            j.addProperty("value", serviceErrorValue(s));
            return j;
        }
        case INITIATEREQUEST: {
            InitiateRequest r = p.initiateRequest;
            j = new JsonObject();
            j.addProperty("kind", "initiate-request");
            j.add("dedicated_key",
                    r.dedicatedKey.isUsed() ? new JsonPrimitive(toHex(r.dedicatedKey.getValue().getValue())) : JsonNull.INSTANCE);
            j.addProperty("response_allowed", r.responseAllowed.getValue().getValue());
            j.add("quality_of_service", r.proposedQualityOfService.isUsed()
                    ? new JsonPrimitive(r.proposedQualityOfService.getValue().getValue())
                    : JsonNull.INSTANCE);
            j.addProperty("dlms_version", r.proposedDlmsVersionNumber.getValue());
            j.addProperty("conformance", conformance(r.proposedConformance));
            j.addProperty("max_receive_pdu_size", r.clientMaxReceivePduSize.getValue());
            return j;
        }
        case INITIATERESPONSE: {
            InitiateResponse r = p.initiateResponse;
            j = new JsonObject();
            j.addProperty("kind", "initiate-response");
            j.add("quality_of_service", r.negotiatedQualityOfService.isUsed()
                    ? new JsonPrimitive(r.negotiatedQualityOfService.getValue().getValue())
                    : JsonNull.INSTANCE);
            j.addProperty("dlms_version", r.negotiatedDlmsVersionNumber.getValue());
            j.addProperty("conformance", conformance(r.negotiatedConformance));
            j.addProperty("max_receive_pdu_size", r.serverMaxReceivePduSize.getValue());
            j.addProperty("vaa_name", r.vaaName.getValue());
            return j;
        }
        case READREQUEST: {
            j = new JsonObject();
            j.addProperty("kind", "read-request");
            JsonArray items = new JsonArray();
            for (VariableAccessSpecification v : p.readRequest.list()) {
                items.add(variable(v));
            }
            j.add("items", items);
            return j;
        }
        case READRESPONSE: {
            j = new JsonObject();
            j.addProperty("kind", "read-response");
            JsonArray rs = new JsonArray();
            for (ReadResponse.SubChoice c : p.readResponse.list()) {
                JsonObject r = new JsonObject();
                r.addProperty("kind", "read-result");
                switch (c.getChoiceIndex()) {
                case DATA:
                    r.add("data", dataJson(c.data));
                    break;
                case DATA_ACCESS_ERROR:
                    r.addProperty("error", c.dataAccessError.getValue());
                    break;
                case DATA_BLOCK_RESULT:
                    r.addProperty("block_last", c.dataBlockResult.lastBlock.getValue());
                    r.addProperty("block_number", c.dataBlockResult.blockNumber.getValue());
                    r.addProperty("raw_data", toHex(c.dataBlockResult.rawData.getValue()));
                    break;
                default:
                    r.addProperty("block_number", c.blockNumber.getValue());
                }
                rs.add(r);
            }
            j.add("results", rs);
            return j;
        }
        case WRITEREQUEST:
            return writeLike("write-request", p.writeRequest.variableAccessSpecification.list(),
                    p.writeRequest.listOfData.list());
        case UNCONFIRMEDWRITEREQUEST:
            return writeLike("unconfirmed-write-request", p.unconfirmedWriteRequest.variableAccessSpecification.list(),
                    p.unconfirmedWriteRequest.listOfData.list());
        case WRITERESPONSE: {
            j = new JsonObject();
            j.addProperty("kind", "write-response");
            JsonArray rs = new JsonArray();
            for (WriteResponse.SubChoice c : p.writeResponse.list()) {
                switch (c.getChoiceIndex()) {
                case SUCCESS:
                    rs.add(0);
                    break;
                case DATA_ACCESS_ERROR:
                    rs.add(c.dataAccessError.getValue());
                    break;
                default: {
                    JsonObject b = new JsonObject();
                    b.addProperty("kind", "write-block-number");
                    b.addProperty("block_number", c.blockNumber.getValue());
                    rs.add(b);
                }
                }
            }
            j.add("results", rs);
            return j;
        }
        case INFORMATIONREPORTREQUEST: {
            InformationReportRequest r = p.informationReportRequest;
            j = new JsonObject();
            j.addProperty("kind", "information-report-request");
            j.add("current_time",
                    r.currentTime.isUsed() ? new JsonPrimitive(toHex(r.currentTime.getValue().getValue())) : JsonNull.INSTANCE);
            JsonArray names = new JsonArray();
            for (VariableAccessSpecification v : r.variableAccessSpecification.list()) {
                if (v.getChoiceIndex() != VariableAccessSpecification.Choices.VARIABLE_NAME) {
                    throw new Unsupported("information-report with non variable-name");
                }
                names.add(v.variableName.getValue() & 0xffff);
            }
            j.add("names", names);
            JsonArray values = new JsonArray();
            for (Data d : r.listOfData.list()) {
                values.add(dataJson(d));
            }
            j.add("values", values);
            return j;
        }
        case GENERAL_BLOCK_TRANSFER: {
            GeneralBlockTransfer g = p.generalBlockTransfer;
            int bc = (int) g.blockControl.getValue();
            j = new JsonObject();
            j.addProperty("kind", "gbt-block");
            j.addProperty("last", (bc & 0x80) != 0);
            j.addProperty("streaming", (bc & 0x40) != 0);
            j.addProperty("window", bc & 0x3f);
            j.addProperty("block_number", g.blockNumber.getValue());
            j.addProperty("block_number_ack", g.blockNumberAck.getValue());
            j.addProperty("data", toHex(g.blockData.getValue()));
            return j;
        }
        default:
            throw new Unsupported("no JSON mapping for jDLMS choice " + p.getChoiceIndex());
        }
    }

    static JsonArray attrList(List<CosemAttributeDescriptorWithSelection> ds, List<Data> values) {
        JsonArray items = new JsonArray();
        for (int i = 0; i < ds.size(); i++) {
            JsonArray t = new JsonArray();
            t.add(attr(ds.get(i).cosemAttributeDescriptor));
            t.add(access(ds.get(i).accessSelection));
            if (values != null) {
                t.add(i < values.size() ? dataJson(values.get(i)) : JsonNull.INSTANCE);
            }
            items.add(t);
        }
        return items;
    }

    static JsonObject variable(VariableAccessSpecification v) {
        JsonObject j = new JsonObject();
        switch (v.getChoiceIndex()) {
        case VARIABLE_NAME:
            j.addProperty("kind", "variable-name");
            j.addProperty("name", v.variableName.getValue() & 0xffff);
            return j;
        case PARAMETERIZED_ACCESS:
            j.addProperty("kind", "parameterized-access");
            j.addProperty("name", v.parameterizedAccess.variableName.getValue() & 0xffff);
            j.addProperty("selector", v.parameterizedAccess.selector.getValue());
            j.add("parameter", dataJson(v.parameterizedAccess.parameter));
            return j;
        case BLOCK_NUMBER_ACCESS:
            j.addProperty("kind", "block-number-access");
            j.addProperty("block_number", v.blockNumberAccess.blockNumber.getValue());
            return j;
        case READ_DATA_BLOCK_ACCESS:
            j.addProperty("kind", "read-data-block-access");
            j.addProperty("last_block", v.readDataBlockAccess.lastBlock.getValue());
            j.addProperty("block_number", v.readDataBlockAccess.blockNumber.getValue());
            j.addProperty("raw_data", toHex(v.readDataBlockAccess.rawData.getValue()));
            return j;
        case WRITE_DATA_BLOCK_ACCESS:
            j.addProperty("kind", "write-data-block-access");
            j.addProperty("last_block", v.writeDataBlockAccess.lastBlock.getValue());
            j.addProperty("block_number", v.writeDataBlockAccess.blockNumber.getValue());
            return j;
        default:
            throw new Unsupported("variable-access-specification " + v.getChoiceIndex());
        }
    }

    static JsonObject writeLike(String kind, List<VariableAccessSpecification> specs, List<Data> data) {
        JsonObject j = new JsonObject();
        j.addProperty("kind", kind);
        JsonArray items = new JsonArray();
        for (VariableAccessSpecification v : specs) {
            items.add(variable(v));
        }
        j.add("items", items);
        JsonArray values = new JsonArray();
        for (Data d : data) {
            values.add(dataJson(d));
        }
        j.add("values", values);
        return j;
    }

    static long conformance(Conformance c) {
        long v = 0;
        for (byte b : c.value) {
            v = (v << 8) | (b & 0xff);
        }
        return v;
    }

    static ServiceError serviceError(ConfirmedServiceError c) {
        ServiceError[] all = { c.initiateError, c.getStatus, c.getNameList, c.getVariableAttribute, c.read, c.write,
                c.getDataSetAttribute, c.getTIAttribute, c.changeScope, c.start, c.stop, c.resume, c.makeUsable,
                c.initiateLoad, c.loadSegment, c.terminateLoad, c.initiateUpLoad, c.upLoadSegment,
                c.terminateUpLoad };
        for (ServiceError s : all) {
            if (s != null) {
                return s;
            }
        }
        throw new IllegalStateException("no service error");
    }

    static long serviceErrorValue(ServiceError s) {
        org.openmuc.jdlms.internal.asn1.axdr.types.AxdrEnum[] all = { s.applicationReference, s.hardwareResource,
                s.vdeStateError, s.service, s.definition, s.access, s.initiate, s.loadDataSet, s.task };
        for (org.openmuc.jdlms.internal.asn1.axdr.types.AxdrEnum e : all) {
            if (e != null) {
                return e.getValue();
            }
        }
        throw new IllegalStateException("no service error value");
    }

    // ---------------------------------------------------------- push / crypto

    static JsonElement opPush(byte[] raw, byte[] ek, byte[] ak) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        COSEMpdu p = new COSEMpdu();
        p.decode(in);
        if (p.getChoiceIndex() == COSEMpdu.Choices.GENERAL_GLO_CIPHERING) {
            if (ek == null || ek.length == 0) {
                throw new IOException("ciphered push without a key");
            }
            byte[] plain = GcmModule.decrypt(p.generalGloCiphering.cipheredContent.getValue(),
                    p.generalGloCiphering.systemTitle.getValue(),
                    suite(p.generalGloCiphering.cipheredContent.getValue()[0], ek, ak));
            in = new ByteArrayInputStream(plain);
            p = new COSEMpdu();
            p.decode(in);
        }
        else if (p.getChoiceIndex() != COSEMpdu.Choices.DATA_NOTIFICATION) {
            throw new Unsupported("push in " + p.getChoiceIndex() + " (only general-glo-ciphering unwrapped)");
        }
        if (in.available() > 0) {
            throw new IOException(in.available() + " trailing octets");
        }
        if (p.getChoiceIndex() != COSEMpdu.Choices.DATA_NOTIFICATION) {
            throw new IOException("not a DataNotification: " + p.getChoiceIndex());
        }
        DataNotification n = p.dataNotification;
        JsonObject j = new JsonObject();
        j.addProperty("long_invoke_id", n.longInvokeIdAndPriority.getValue());
        byte[] dt = n.dateTime.getValue();
        j.add("date_time", dt.length == 0 ? JsonNull.INSTANCE : new JsonPrimitive(toHex(dt)));
        j.add("body", dataJson(n.notificationBody.dataValue));
        return j;
    }

    /**
     * jDLMS derives the GCM AAD from a configured SecuritySuite, not from the
     * received security control byte, so the suite is built from that byte as a
     * client configured for this meter would be.
     */
    static SecuritySuite suite(byte sc, byte[] ek, byte[] ak) {
        boolean auth = (sc & 0x10) != 0;
        boolean enc = (sc & 0x20) != 0;
        SecurityPolicy policy = auth && enc ? SecurityPolicy.AUTHENTICATED_AND_ENCRYPTED
                : auth ? SecurityPolicy.AUTHENTICATED : enc ? SecurityPolicy.ENCRYPTED : SecurityPolicy.NOTHING;
        return SecuritySuite.builder()
                .setGlobalUnicastEncryptionKey(ek)
                .setAuthenticationKey(ak != null && ak.length > 0 ? ak : ek)
                .setEncryptionMechanism(EncryptionMechanism.getInstance(sc & 0x0f))
                .setAuthenticationMechanism(AuthenticationMechanism.HLS5_GMAC)
                .setSecurityPolicy(policy)
                .build();
    }

    static byte[] decrypt(byte[] ek, byte[] ak, byte[] title, byte[] raw) throws IOException {
        COSEMpdu p = new COSEMpdu();
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        p.decode(in);
        byte[] content;
        if (p.getChoiceIndex() == COSEMpdu.Choices.GENERAL_GLO_CIPHERING) {
            title = p.generalGloCiphering.systemTitle.getValue();
            content = p.generalGloCiphering.cipheredContent.getValue();
        }
        else {
            content = gloContent(p);
        }
        if (in.available() > 0) {
            throw new IOException(in.available() + " trailing octets");
        }
        return GcmModule.decrypt(content, title, suite(content[0], ek, ak));
    }

    /** The octet string of any glo-/ded- choice, found by jDLMS's field naming. */
    static byte[] gloContent(COSEMpdu p) throws IOException {
        for (java.lang.reflect.Field f : COSEMpdu.class.getFields()) {
            String n = f.getName();
            if ((n.startsWith("glo") || n.startsWith("ded")) && f.getType() == AxdrOctetString.class) {
                try {
                    Object v = f.get(p);
                    if (v != null) {
                        return ((AxdrOctetString) v).getValue();
                    }
                } catch (IllegalAccessException e) {
                    throw new IOException(e);
                }
            }
        }
        throw new Unsupported("not a glo-/ded-/general-glo-ciphered APDU: " + p.getChoiceIndex());
    }

    // ----------------------------------------------------------------- hex

    /** A key or system-title argument; {@code -} means absent (PROTOCOL.md). */
    static byte[] key(String s) {
        return "-".equals(s) ? null : hex(s);
    }

    static byte[] hex(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }
}
