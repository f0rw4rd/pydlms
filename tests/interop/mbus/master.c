/*
 * libmbus (rscada/libmbus) as an independent wired M-Bus master for
 * pydlms's MbusServer: SND_NKE (or a secondary selection), then for every
 * APDU given in hex one SND_UD with CI 0x10 (STSAP 16, DTSAP 1) and
 * REQ_UD2 polls with toggling FCB until a final DLMS segment (CI bit 4)
 * arrives. Frames are built by mbus_frame_pack and received through
 * mbus_recv_frame, whose mbus_parse runs mbus_frame_verify (start, L,
 * C field set, checksum, stop). Output, one line per telegram:
 *
 *   ACK <what>
 *   RSP <C> <A> <CI> <data hex>
 *   IDLE <secondary address libmbus parsed from a CI 0x72 answer>
 *   ERR <what> <libmbus error>
 *
 * Usage: mbus-dlms-master HOST PORT ADDRESS [--secondary ID16] APDU_HEX...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbus/mbus.h>

static int expect_ack(mbus_handle *h, const char *what)
{
    mbus_frame reply;
    memset(&reply, 0, sizeof(reply));
    if (mbus_recv_frame(h, &reply) != MBUS_RECV_RESULT_OK || reply.type != MBUS_FRAME_TYPE_ACK) {
        printf("ERR %s %s\n", what, mbus_error_str());
        return -1;
    }
    printf("ACK %s\n", what);
    return 0;
}

static int hex2bin(const char *hex, unsigned char *out, size_t max)
{
    size_t n = strlen(hex) / 2, i;
    if (n > max)
        return -1;
    for (i = 0; i < n; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    return (int)n;
}

int main(int argc, char **argv)
{
    mbus_handle *h;
    int address, arg = 4, fcb_snd = 1, fcb_req = 1;

    if (argc < 4) {
        fprintf(stderr, "usage: %s HOST PORT ADDRESS [--secondary ID16] APDU_HEX...\n", argv[0]);
        return 2;
    }
    address = atoi(argv[3]);
    h = mbus_context_tcp(argv[1], (uint16_t)atoi(argv[2]));
    if (!h || mbus_connect(h) == -1) {
        printf("ERR connect %s\n", mbus_error_str());
        return 1;
    }
    mbus_tcp_set_timeout_set(2.0);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (arg < argc && strcmp(argv[arg], "--secondary") == 0) {
        if (mbus_send_select_frame(h, argv[arg + 1]) == -1 || expect_ack(h, "select") < 0)
            return 1;
        address = MBUS_ADDRESS_NETWORK_LAYER;
        arg += 2;
    } else {
        if (mbus_send_ping_frame(h, address, 0) == -1 || expect_ack(h, "SND_NKE") < 0)
            return 1;
    }

    for (; arg < argc; arg++) {
        mbus_frame *frame = mbus_frame_new(MBUS_FRAME_TYPE_LONG);
        int n;
        frame->control = MBUS_CONTROL_MASK_SND_UD | (fcb_snd ? MBUS_CONTROL_MASK_FCB : 0);
        frame->address = address;
        frame->control_information = 0x10; /* DLMS, segment 0, final */
        frame->data[0] = 16;               /* STSAP: public client */
        frame->data[1] = 1;                /* DTSAP: management logical device */
        n = hex2bin(argv[arg], frame->data + 2, sizeof(frame->data) - 2);
        if (n < 0) {
            printf("ERR apdu bad hex\n");
            return 2;
        }
        frame->data_size = (size_t)n + 2;
        if (mbus_send_frame(h, frame) == -1 || expect_ack(h, "SND_UD") < 0)
            return 1;
        mbus_frame_free(frame);
        fcb_snd = !fcb_snd;

        for (int polls = 0; polls < 64; polls++) {
            mbus_frame request, reply;
            unsigned char ci;
            memset(&request, 0, sizeof(request));
            memset(&reply, 0, sizeof(reply));
            request.type = MBUS_FRAME_TYPE_SHORT;
            request.start1 = MBUS_FRAME_SHORT_START;
            request.stop = MBUS_FRAME_STOP;
            request.control = MBUS_CONTROL_MASK_REQ_UD2 | (fcb_req ? MBUS_CONTROL_MASK_FCB : 0);
            request.address = address;
            if (mbus_send_frame(h, &request) == -1)
                return 1;
            if (mbus_recv_frame(h, &reply) != MBUS_RECV_RESULT_OK) {
                printf("ERR REQ_UD2 %s\n", mbus_error_str());
                return 1;
            }
            if (reply.type == MBUS_FRAME_TYPE_ACK) {
                printf("ACK REQ_UD2\n");
                continue;
            }
            fcb_req = !fcb_req;
            ci = reply.control_information;
            printf("RSP %02X %02X %02X ", reply.control, reply.address, ci);
            for (size_t i = 0; i < reply.data_size; i++)
                printf("%02X", reply.data[i]);
            printf("\n");
            if (ci == MBUS_CONTROL_INFO_RESP_VARIABLE) {
                /* No DLMS data yet: libmbus parses the variable data header. */
                char *secondary = mbus_frame_get_secondary_address(&reply);
                printf("IDLE %s\n", secondary ? secondary : mbus_error_str());
            }
            if (ci <= 0x1F && (ci & 0x10))
                break;
        }
    }
    mbus_disconnect(h);
    mbus_context_free(h);
    return 0;
}
