// The Gurux.DLMS.Net *client*
// reading a DLMS server (here `pydlms simulate`) over TCP with the wrapper.
//
//   dotnet gxoracle.dll client HOST PORT none
//   dotnet gxoracle.dll client HOST PORT lls PASSWORD
//   dotnet gxoracle.dll client HOST PORT gmac EK AK
//
// Associates (client SAP 16 / 17 / 1), reads the association's object list,
// then every attribute of every object Gurux knows (GetAttributeIndexToRead),
// a profile-generic range and entry read, and releases. One JSON object per
// step on stdout: {"step", "ok", "ln", "class_id", "attribute", "raw", "error"}
// ("data_access_result" instead of "raw" when the server refused the read).
// "raw" is the A-XDR value as Gurux holds it after the read (GXReplyData.Data).
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;

static class ReverseClient
{
    static GXDLMSSecureClient client;
    static NetworkStream stream;

    static void Emit(JsonObject o)
    {
        Console.Out.WriteLine(o.ToJsonString());
        Console.Out.Flush();
    }

    static string Hex(byte[] b) => Convert.ToHexString(b ?? new byte[0]).ToLowerInvariant();

    static void Packet(byte[] data, GXReplyData reply)
    {
        if (data != null)
        {
            stream.Write(data, 0, data.Length);
        }
        var buffer = new GXByteBuffer();
        var notify = new GXReplyData();
        var chunk = new byte[4096];
        while (!client.GetData(buffer, reply, notify))
        {
            int n = stream.Read(chunk, 0, chunk.Length);
            if (n <= 0)
            {
                throw new Exception("connection closed");
            }
            buffer.Set(chunk, 0, n);
        }
    }

    static GXReplyData Exchange(byte[][] frames)
    {
        var reply = new GXReplyData();
        foreach (byte[] frame in frames)
        {
            reply.Clear();
            Packet(frame, reply);
            while (reply.IsMoreData)
            {
                Packet(reply.IsStreaming() ? null : client.ReceiverReady(reply), reply);
            }
        }
        return reply;
    }

    static JsonObject Step(string name, Func<JsonObject> body)
    {
        var o = new JsonObject { ["step"] = name };
        try
        {
            JsonObject extra = body();
            o["ok"] = true;
            if (extra != null)
            {
                foreach (var kv in extra)
                {
                    o[kv.Key] = kv.Value?.DeepClone();
                }
            }
        }
        catch (Exception e)
        {
            o["ok"] = false;
            o["error"] = e.GetType().Name + ": " + e.Message.Replace("\n", " ");
        }
        Emit(o);
        return o;
    }

    public static int Run(string[] args)
    {
        string host = args[1];
        int port = int.Parse(args[2]);
        string mode = args.Length > 3 ? args[3] : "none";
        if (mode == "gmac")
        {
            client = new GXDLMSSecureClient(true, 1, 1, Authentication.HighGMAC, null, InterfaceType.WRAPPER);
            client.Ciphering.Security = Security.AuthenticationEncryption;
            client.Ciphering.SystemTitle = System.Text.Encoding.ASCII.GetBytes("GXCLIENT");
            client.Ciphering.BlockCipherKey = Convert.FromHexString(args[4]);
            client.Ciphering.AuthenticationKey = Convert.FromHexString(args[5]);
        }
        else if (mode == "lls")
        {
            client = new GXDLMSSecureClient(true, 17, 1, Authentication.Low, args[4], InterfaceType.WRAPPER);
        }
        else
        {
            client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        }
        using var tcp = new TcpClient(host, port);
        tcp.ReceiveTimeout = 15000;
        stream = tcp.GetStream();

        JsonObject assoc = Step("associate", () =>
        {
            GXReplyData r = Exchange(client.AARQRequest());
            client.ParseAAREResponse(r.Data);
            if (client.Authentication > Authentication.Low)
            {
                r = Exchange(client.GetApplicationAssociationRequest());
                client.ParseApplicationAssociationResponse(r.Data);
            }
            return new JsonObject { ["negotiated_conformance"] = (int)client.NegotiatedConformance };
        });
        if (!(bool)assoc["ok"])
        {
            return 1;
        }

        GXDLMSObjectCollection objects = null;
        Step("object-list", () =>
        {
            GXReplyData r = Exchange(client.GetObjectsRequest());
            objects = client.ParseObjects(r.Data, true);
            var list = new JsonArray();
            foreach (GXDLMSObject obj in objects)
            {
                list.Add(new JsonObject
                {
                    ["ln"] = obj.LogicalName,
                    ["class_id"] = (int)obj.ObjectType,
                    ["version"] = obj.Version,
                });
            }
            return new JsonObject { ["objects"] = list };
        });

        foreach (GXDLMSObject obj in objects ?? new GXDLMSObjectCollection())
        {
            foreach (int index in (obj as IGXDLMSBase).GetAttributeIndexToRead(true))
            {
                var o = new JsonObject
                {
                    ["step"] = "read",
                    ["ln"] = obj.LogicalName,
                    ["class_id"] = (int)obj.ObjectType,
                    ["attribute"] = index,
                };
                try
                {
                    GXReplyData r = Exchange(client.Read(obj, index));
                    if (r.Error != 0)
                    {
                        // Data-Access-Result: GetData does not throw for it.
                        o["ok"] = false;
                        o["data_access_result"] = r.Error;
                    }
                    else
                    {
                        o["raw"] = Hex(r.Data.Array());
                        client.UpdateValue(obj, index, r.Value);
                        o["ok"] = true;
                    }
                }
                catch (Exception e)
                {
                    o["ok"] = false;
                    o["error"] = e.GetType().Name + ": " + e.Message.Replace("\n", " ");
                }
                Emit(o);
            }
        }

        foreach (GXDLMSObject obj in objects ?? new GXDLMSObjectCollection())
        {
            if (obj is GXDLMSProfileGeneric pg)
            {
                Step("profile-entry", () =>
                {
                    GXReplyData r = Exchange(client.ReadRowsByEntry(pg, 2, 3));
                    return new JsonObject { ["ln"] = pg.LogicalName, ["raw"] = Hex(r.Data.Array()) };
                });
                Step("profile-range", () =>
                {
                    var start = new GXDateTime(new DateTimeOffset(2024, 5, 1, 1, 0, 0, TimeSpan.Zero));
                    var end = new GXDateTime(new DateTimeOffset(2024, 5, 1, 2, 0, 0, TimeSpan.Zero));
                    GXReplyData r = Exchange(client.ReadRowsByRange(pg, start, end));
                    return new JsonObject { ["ln"] = pg.LogicalName, ["raw"] = Hex(r.Data.Array()) };
                });
            }
        }

        Step("release", () =>
        {
            Exchange(client.ReleaseRequest());
            return null;
        });
        return 0;
    }
}
