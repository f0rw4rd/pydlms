/*
 * Oracle adapter for GuruxDLMS.c (tests/interop/PROTOCOL.md): one request per
 * stdin line, one JSON object per stdout line. Written for the pydlms
 * harness; links the unmodified library (libgurux_dlms_c.a) and calls only
 * its public decoder dlms_getData() (and dlms_setData() to print date/time
 * values back as octets, since the decoder keeps them as gxtime).
 *
 * Ops: hello, data. Everything else answers "unsupported": the C library has
 * no APDU translator and no push/decrypt entry point usable without a full
 * client session.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bytebuffer.h"
#include "datainfo.h"
#include "dlms.h"
#include "serverevents.h"
#include "variant.h"

/* dlms.c references two server callbacks even when only the codec is used;
 * the adapter never runs a server, so they are never called. */
unsigned char svr_isTarget(dlmsSettings* settings, uint32_t serverAddress, uint32_t clientAddress)
{
    (void)settings, (void)serverAddress, (void)clientAddress;
    return 0;
}

int svr_connected(dlmsServerSettings* settings)
{
    (void)settings;
    return 0;
}

#ifndef GURUX_C_COMMIT
#define GURUX_C_COMMIT "unknown"
#endif

typedef struct
{
    char* p;
    size_t n, cap;
} sbuf;

static void put(sbuf* s, const char* fmt, ...)
{
    va_list ap;
    for (;;)
    {
        va_start(ap, fmt);
        int k = vsnprintf(s->p + s->n, s->cap - s->n, fmt, ap);
        va_end(ap);
        if (k >= 0 && (size_t)k < s->cap - s->n)
        {
            s->n += (size_t)k;
            return;
        }
        s->cap = s->cap * 2 + (size_t)(k > 0 ? k : 64);
        s->p = realloc(s->p, s->cap);
        if (s->p == NULL)
        {
            exit(2);
        }
    }
}

static void put_hex(sbuf* s, const unsigned char* d, size_t n)
{
    put(s, "\"");
    for (size_t i = 0; i < n; ++i)
    {
        put(s, "%02x", d[i]);
    }
    put(s, "\"");
}

/* JSON string of raw octets: ASCII as is, everything else \u00XX (latin-1),
 * the convention of tests/interop/model.py for visible-string. */
static void put_text(sbuf* s, const unsigned char* d, size_t n, int utf8)
{
    put(s, "\"");
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char c = d[i];
        if (c == '"' || c == '\\')
        {
            put(s, "\\%c", c);
        }
        else if (c < 0x20 || c == 0x7f || (c >= 0x80 && !utf8))
        {
            put(s, "\\u%04x", c);
        }
        else
        {
            put(s, "%c", c);
        }
    }
    put(s, "\"");
}

static const char* type_name(int vt)
{
    switch (vt)
    {
    case DLMS_DATA_TYPE_NONE: return "null-data";
    case DLMS_DATA_TYPE_ARRAY: return "array";
    case DLMS_DATA_TYPE_STRUCTURE: return "structure";
    case DLMS_DATA_TYPE_BOOLEAN: return "boolean";
    case DLMS_DATA_TYPE_BIT_STRING: return "bit-string";
    case DLMS_DATA_TYPE_INT32: return "double-long";
    case DLMS_DATA_TYPE_UINT32: return "double-long-unsigned";
    case DLMS_DATA_TYPE_OCTET_STRING: return "octet-string";
    case DLMS_DATA_TYPE_STRING: return "visible-string";
    case DLMS_DATA_TYPE_STRING_UTF8: return "utf8-string";
    case DLMS_DATA_TYPE_BINARY_CODED_DESIMAL: return "bcd";
    case DLMS_DATA_TYPE_INT8: return "integer";
    case DLMS_DATA_TYPE_INT16: return "long";
    case DLMS_DATA_TYPE_UINT8: return "unsigned";
    case DLMS_DATA_TYPE_UINT16: return "long-unsigned";
    case DLMS_DATA_TYPE_COMPACT_ARRAY: return "compact-array";
    case DLMS_DATA_TYPE_INT64: return "long64";
    case DLMS_DATA_TYPE_UINT64: return "long64-unsigned";
    case DLMS_DATA_TYPE_ENUM: return "enum";
    case DLMS_DATA_TYPE_FLOAT32: return "float32";
    case DLMS_DATA_TYPE_FLOAT64: return "float64";
    case DLMS_DATA_TYPE_DATETIME: return "date-time";
    case DLMS_DATA_TYPE_DATE: return "date";
    case DLMS_DATA_TYPE_TIME: return "time";
    default: return NULL;
    }
}

static int put_tree(sbuf* s, dlmsVARIANT* v);

static int put_value(sbuf* s, dlmsVARIANT* v)
{
    int i;
    switch (v->vt)
    {
    case DLMS_DATA_TYPE_NONE: put(s, "null"); return 0;
    case DLMS_DATA_TYPE_BOOLEAN: put(s, v->boolVal ? "true" : "false"); return 0;
    case DLMS_DATA_TYPE_INT8: put(s, "%d", v->cVal); return 0;
    case DLMS_DATA_TYPE_INT16: put(s, "%d", v->iVal); return 0;
    case DLMS_DATA_TYPE_INT32: put(s, "%ld", (long)v->lVal); return 0;
    case DLMS_DATA_TYPE_INT64: put(s, "%lld", (long long)v->llVal); return 0;
    case DLMS_DATA_TYPE_UINT8:
    case DLMS_DATA_TYPE_ENUM: put(s, "%u", v->bVal); return 0;
    case DLMS_DATA_TYPE_UINT16: put(s, "%u", v->uiVal); return 0;
    case DLMS_DATA_TYPE_UINT32: put(s, "%lu", (unsigned long)v->ulVal); return 0;
    case DLMS_DATA_TYPE_UINT64: put(s, "%llu", (unsigned long long)v->ullVal); return 0;
    case DLMS_DATA_TYPE_FLOAT32:
    {
        unsigned char b[4], *p = (unsigned char*)&v->fltVal;
        for (i = 0; i < 4; ++i)
        {
            b[i] = p[3 - i];
        }
        put_hex(s, b, 4);
        return 0;
    }
    case DLMS_DATA_TYPE_FLOAT64:
    {
        unsigned char b[8], *p = (unsigned char*)&v->dblVal;
        for (i = 0; i < 8; ++i)
        {
            b[i] = p[7 - i];
        }
        put_hex(s, b, 8);
        return 0;
    }
    case DLMS_DATA_TYPE_OCTET_STRING:
        put_hex(s, v->byteArr ? v->byteArr->data : NULL, v->byteArr ? v->byteArr->size : 0);
        return 0;
    case DLMS_DATA_TYPE_STRING:
        put_text(s, v->strVal ? v->strVal->data : NULL, v->strVal ? v->strVal->size : 0, 0);
        return 0;
    case DLMS_DATA_TYPE_STRING_UTF8:
        put_text(s, v->strUtfVal ? v->strUtfVal->data : NULL,
            v->strUtfVal ? v->strUtfVal->size : 0, 1);
        return 0;
    case DLMS_DATA_TYPE_BIT_STRING:
    {
        put(s, "\"");
        for (i = 0; v->bitArr && i < v->bitArr->size; ++i)
        {
            unsigned char bit = 0;
            ba_getByIndex(v->bitArr, i, &bit);
            put(s, bit ? "1" : "0");
        }
        put(s, "\"");
        return 0;
    }
    case DLMS_DATA_TYPE_DATETIME:
    case DLMS_DATA_TYPE_DATE:
    case DLMS_DATA_TYPE_TIME:
    {
        /* The decoder keeps a gxtime; the library's own encoder gives the
         * octets back (tag first, no length). */
        gxByteBuffer bb;
        dlmsVARIANT copy;
        int ret;
        BYTE_BUFFER_INIT(&bb);
        var_init(&copy);
        if ((ret = var_copy(&copy, v)) != 0 || (ret = dlms_setData(&bb, v->vt, &copy)) != 0)
        {
            var_clear(&copy);
            bb_clear(&bb);
            return ret;
        }
        put_hex(s, bb.data + 1, bb.size - 1);
        var_clear(&copy);
        bb_clear(&bb);
        return 0;
    }
    case DLMS_DATA_TYPE_ARRAY:
    case DLMS_DATA_TYPE_STRUCTURE:
    {
        put(s, "[");
        for (i = 0; v->Arr && i < v->Arr->size; ++i)
        {
            dlmsVARIANT* item;
            int ret;
            if ((ret = va_getByIndex(v->Arr, i, &item)) != 0)
            {
                return ret;
            }
            if (i)
            {
                put(s, ",");
            }
            if ((ret = put_tree(s, item)) != 0)
            {
                return ret;
            }
        }
        put(s, "]");
        return 0;
    }
    default:
        return -1;
    }
}

static int put_tree(sbuf* s, dlmsVARIANT* v)
{
    const char* name = type_name(v->vt);
    if (name == NULL)
    {
        return -1;
    }
    put(s, "{\"t\":\"%s\",\"v\":", name);
    int ret = put_value(s, v);
    put(s, "}");
    return ret;
}

static int unhex(const char* h, gxByteBuffer* out)
{
    size_t n = strlen(h);
    if (n % 2)
    {
        return -1;
    }
    for (size_t i = 0; i < n; i += 2)
    {
        unsigned int b;
        if (sscanf(h + i, "%2x", &b) != 1)
        {
            return -1;
        }
        bb_setUInt8(out, (unsigned char)b);
    }
    return 0;
}

static void reply_error(const char* msg, int unsupported)
{
    sbuf s = { malloc(256), 0, 256 };
    put(&s, "{\"ok\":false,%s\"error\":", unsupported ? "\"unsupported\":true," : "");
    put_text(&s, (const unsigned char*)msg, strlen(msg), 0);
    put(&s, "}");
    puts(s.p);
    free(s.p);
}

static void op_data(const char* hex)
{
    gxByteBuffer bb;
    gxDataInfo info;
    dlmsVARIANT value;
    char msg[96];
    BYTE_BUFFER_INIT(&bb);
    di_init(&info);
    var_init(&value);
    if (unhex(hex, &bb) != 0)
    {
        reply_error("bad hex", 0);
    }
    else if (bb.size > 0 && bb.data[0] == DLMS_DATA_TYPE_COMPACT_ARRAY)
    {
        /* dlms_getData flattens a compact-array to an array of items and
         * drops the type description, which the JSON model needs. */
        reply_error("compact-array: decoder drops the type description", 1);
    }
    else
    {
        int ret = dlms_getData(&bb, &info, &value);
        if (ret != 0)
        {
            snprintf(msg, sizeof msg, "dlms_getData error %d", ret);
            reply_error(msg, 0);
        }
        else if (!info.complete)
        {
            reply_error("dlms_getData: incomplete", 0);
        }
        else if (bb.position != bb.size)
        {
            /* Adapter policy, as model.py: one value, nothing after it. */
            snprintf(msg, sizeof msg, "%u trailing octets", (unsigned)(bb.size - bb.position));
            reply_error(msg, 0);
        }
        else
        {
            sbuf s = { malloc(1024), 0, 1024 };
            put(&s, "{\"ok\":true,\"result\":");
            if (put_tree(&s, &value) != 0)
            {
                snprintf(msg, sizeof msg, "adapter cannot print variant type %d", value.vt);
                reply_error(msg, 0);
            }
            else
            {
                put(&s, "}");
                puts(s.p);
            }
            free(s.p);
        }
    }
    var_clear(&value);
    bb_clear(&bb);
}

int main(void)
{
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin) != NULL)
    {
        line[strcspn(line, "\r\n")] = 0;
        char* arg = strchr(line, ' ');
        if (arg)
        {
            *arg++ = 0;
        }
        if (strcmp(line, "hello") == 0)
        {
            printf("{\"ok\":true,\"library\":\"GuruxDLMS.c\",\"version\":\"%s\",\"ops\":[\"data\"]}\n",
                GURUX_C_COMMIT);
        }
        else if (strcmp(line, "data") == 0 && arg)
        {
            op_data(arg);
        }
        else
        {
            reply_error("op not implemented by the GuruxDLMS.c adapter", 1);
        }
        fflush(stdout);
    }
    return 0;
}
