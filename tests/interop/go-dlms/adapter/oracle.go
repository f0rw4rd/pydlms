package main

// The oracle line protocol (tests/interop/PROTOCOL.md) over stdin/stdout.
//
// apdu: gosem's DecodeCosem for the xDLMS services (the codec the library
// uses), gosem's DecodeAARE/DecodeRLRE/DecodeInitiateResponse, and the
// library server's own AARQ/InitiateRequest parsers (server/aa.go).
// push: cosem.DecodeDataNotification and cosem.OpenProtectedPush.
// decrypt: the client's opening path (cosem/secure.go incoming).

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/server"
)

const libraryVersion = "26360a13e5d8f1da0fba1758118adaaa00be2ccf (v0.3.0; gosem v1.3.4)"

type unsupportedError string

func (e unsupportedError) Error() string { return string(e) }

func errUnsupported(msg string) error { return unsupportedError(msg) }

func runOracle() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		b, _ := json.Marshal(answer(line))
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
}

func answer(line string) (reply map[string]any) {
	op, rest, _ := strings.Cut(line, " ")
	args := strings.Fields(rest)
	defer func() {
		if r := recover(); r != nil {
			reply = map[string]any{"ok": false, "error": fmt.Sprintf("panic: %v", r)}
		}
	}()
	var result any
	var err error
	switch op {
	case "hello":
		return map[string]any{"ok": true, "library": "github.com/cB-Sigma/dlms", "version": libraryVersion,
			"ops": []string{"data", "encode-data", "apdu", "push", "decrypt"}}
	case "data":
		result, err = opData(args)
	case "encode-data":
		result, err = opEncodeData(rest)
	case "apdu":
		result, err = opAPDU(args)
	case "push":
		result, err = opPush(args)
	case "decrypt":
		result, err = opDecrypt(args)
	default:
		err = errUnsupported("unknown op " + op)
	}
	var u unsupportedError
	switch {
	case errors.As(err, &u):
		return map[string]any{"ok": false, "unsupported": true, "error": err.Error()}
	case err != nil:
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true, "result": result}
}

func hexArg(args []string, i int) ([]byte, error) {
	if i >= len(args) {
		return nil, fmt.Errorf("missing argument %d", i+1)
	}
	return hex.DecodeString(args[i])
}

// keyArg decodes a key or system-title argument; "-" (or a missing
// argument) means absent (PROTOCOL.md).
func keyArg(args []string, i int) ([]byte, error) {
	if i >= len(args) || args[i] == "-" {
		return nil, nil
	}
	return hex.DecodeString(args[i])
}

func opData(args []string) (any, error) {
	b, err := hexArg(args, 0)
	if err != nil {
		return nil, err
	}
	d, err := decodeOne(b)
	if err != nil {
		return nil, err
	}
	return toTree(d)
}

func opEncodeData(rest string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(rest))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	d, err := fromTree(obj)
	if err != nil {
		return nil, err
	}
	b, err := encode(d)
	if err != nil {
		return nil, err
	}
	return map[string]any{"hex": hex.EncodeToString(b)}, nil
}

// --- APDUs ---------------------------------------------------------------

func attr(a gdlms.AttributeDescriptor) tree {
	return tree{"kind": "attribute-descriptor", "class_id": a.ClassID, "instance_id": a.InstanceID.String(),
		"attribute_id": a.AttributeID}
}

func method(m gdlms.MethodDescriptor) tree {
	return tree{"kind": "method-descriptor", "class_id": m.ClassID, "instance_id": m.InstanceID.String(),
		"method_id": m.MethodID}
}

func access(s *gdlms.SelectiveAccessDescriptor) (any, error) {
	if s == nil {
		return nil, nil
	}
	p, err := toTree(&s.AccessParameter)
	if err != nil {
		return nil, err
	}
	return tree{"kind": "selective-access", "selector": uint8(s.AccessSelector), "parameters": p}, nil
}

func dataTree(d axdr.DlmsData) (any, error) { return toTree(&d) }

func getDataResult(r gdlms.GetDataResult) (tree, error) {
	if !r.IsData {
		code, _ := r.Value.(gdlms.AccessResultTag)
		return tree{"kind": "get-data-result", "data": nil, "error": uint8(code)}, nil
	}
	d, ok := r.Value.(axdr.DlmsData)
	if !ok {
		return nil, fmt.Errorf("get-data-result holds %T", r.Value)
	}
	t, err := toTree(&d)
	if err != nil {
		return nil, err
	}
	return tree{"kind": "get-data-result", "data": t, "error": nil}, nil
}

func blockSA(kind string, invoke uint8, b gdlms.DataBlockSA) tree {
	return tree{"kind": kind, "invoke_id": invoke, "last_block": b.LastBlock, "block_number": b.BlockNumber,
		"raw_data": hex.EncodeToString(b.Raw)}
}

func withSelection(a gdlms.AttributeDescriptorWithSelection) (tree, any, error) {
	acc, err := access(a.AccessDescriptor)
	return attr(gdlms.AttributeDescriptor{ClassID: a.ClassID, InstanceID: a.InstanceID, AttributeID: a.AttributeID}), acc, err
}

func opAPDU(args []string) (any, error) {
	b, err := hexArg(args, 0)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty APDU")
	}
	switch b[0] {
	case 0x60:
		return aarq(b)
	case 0x01:
		return initiateRequest(b)
	case 0x61:
		src := b
		a, err := gdlms.DecodeAARE(nil, &src)
		if err != nil {
			return nil, err
		}
		if len(src) != 0 {
			return nil, fmt.Errorf("%d trailing octets", len(src))
		}
		out := tree{"kind": "aare", "application_context": uint8(a.ApplicationContext),
			"result": uint8(a.AssociationResult), "diagnostic": uint8(a.SourceDiagnostic)}
		if a.SourceSystemTitle != nil {
			out["responding_ap_title"] = hex.EncodeToString(a.SourceSystemTitle)
		} else {
			out["responding_ap_title"] = nil
		}
		return out, nil
	case 0x63:
		src := b
		r, err := gdlms.DecodeRLRE(&src)
		if err != nil {
			return nil, err
		}
		out := tree{"kind": "rlre", "reason": nil}
		if r.ReleaseResponseReason != nil {
			out["reason"] = uint8(*r.ReleaseResponseReason)
		}
		return out, nil
	case 0x08:
		src := b
		r, err := gdlms.DecodeInitiateResponse(&src)
		if err != nil {
			return nil, err
		}
		if len(src) != 0 {
			return nil, fmt.Errorf("%d trailing octets", len(src))
		}
		out := tree{"kind": "initiate-response", "conformance": r.NegotiatedConformance,
			"max_receive_pdu_size": r.ServerMaxReceivePduSize, "dlms_version": gdlms.DlmsVersion,
			"quality_of_service": nil}
		if r.NegotiatedQualityOfService != nil {
			out["quality_of_service"] = *r.NegotiatedQualityOfService
		}
		return out, nil
	}
	if !knownCosem[b[0]] {
		return nil, errUnsupported(fmt.Sprintf("tag %#x: no decoder in gosem or the library", b[0]))
	}
	src := b
	pdu, err := gdlms.DecodeCosem(&src)
	if err != nil {
		return nil, err
	}
	if len(src) != 0 {
		return nil, fmt.Errorf("%d trailing octets", len(src))
	}
	return pduTree(pdu)
}

var knownCosem = map[byte]bool{0x0E: true, 0x0F: true, 0xC0: true, 0xC1: true, 0xC2: true, 0xC3: true,
	0xC4: true, 0xC5: true, 0xC7: true, 0xD8: true}

func pduTree(pdu gdlms.CosemPDU) (any, error) {
	switch p := pdu.(type) {
	case gdlms.GetRequestNormal:
		acc, err := access(p.SelectiveAccessInfo)
		return tree{"kind": "get-request-normal", "invoke_id": p.InvokePriority, "attribute": attr(p.AttributeInfo),
			"access": acc}, err
	case gdlms.GetRequestNext:
		return tree{"kind": "get-request-next", "invoke_id": p.InvokePriority, "block_number": p.BlockNum}, nil
	case gdlms.GetRequestWithList:
		items := []any{}
		for _, a := range p.AttributeInfoList {
			at, acc, err := withSelection(a)
			if err != nil {
				return nil, err
			}
			items = append(items, []any{at, acc})
		}
		return tree{"kind": "get-request-with-list", "invoke_id": p.InvokePriority, "items": items}, nil
	case gdlms.GetResponseNormal:
		r, err := getDataResult(p.Result)
		return tree{"kind": "get-response-normal", "invoke_id": p.InvokePriority, "result": r}, err
	case gdlms.GetResponseWithDataBlock:
		out := tree{"kind": "get-response-with-datablock", "invoke_id": p.InvokePriority,
			"last_block": p.Result.LastBlock, "block_number": p.Result.BlockNumber}
		if p.Result.IsResult {
			code, _ := p.Result.Result.(gdlms.AccessResultTag)
			out["raw_data"], out["error"] = nil, uint8(code)
		} else {
			raw, _ := p.Result.Result.([]byte)
			out["raw_data"] = hex.EncodeToString(raw)
		}
		return out, nil
	case gdlms.GetResponseWithList:
		results := []any{}
		for _, r := range p.ResultList {
			t, err := getDataResult(r)
			if err != nil {
				return nil, err
			}
			results = append(results, t)
		}
		return tree{"kind": "get-response-with-list", "invoke_id": p.InvokePriority, "results": results}, nil
	case gdlms.SetRequestNormal:
		acc, err := access(p.SelectiveAccessInfo)
		if err != nil {
			return nil, err
		}
		v, err := dataTree(p.Value)
		return tree{"kind": "set-request-normal", "invoke_id": p.InvokePriority, "attribute": attr(p.AttributeInfo),
			"access": acc, "value": v}, err
	case gdlms.SetRequestWithFirstDataBlock:
		acc, err := access(p.SelectiveAccessInfo)
		out := blockSA("set-request-with-first-datablock", p.InvokePriority, p.DataBlock)
		out["attribute"], out["access"] = attr(p.AttributeInfo), acc
		return out, err
	case gdlms.SetRequestWithDataBlock:
		return blockSA("set-request-with-datablock", p.InvokePriority, p.DataBlock), nil
	case gdlms.SetRequestWithList:
		if len(p.AttributeInfoList) != len(p.ValueList) {
			return nil, fmt.Errorf("%d attributes, %d values", len(p.AttributeInfoList), len(p.ValueList))
		}
		items := []any{}
		for i, a := range p.AttributeInfoList {
			at, acc, err := withSelection(a)
			if err != nil {
				return nil, err
			}
			v, err := dataTree(p.ValueList[i])
			if err != nil {
				return nil, err
			}
			items = append(items, []any{at, acc, v})
		}
		return tree{"kind": "set-request-with-list", "invoke_id": p.InvokePriority, "items": items}, nil
	case gdlms.SetRequestWithListAndFirstDataBlock:
		return blockSA("set-request-with-list-and-first-datablock", p.InvokePriority, p.DataBlock), nil
	case gdlms.SetResponseNormal:
		return tree{"kind": "set-response-normal", "invoke_id": p.InvokePriority, "result": uint8(p.Result)}, nil
	case gdlms.SetResponseDataBlock:
		return tree{"kind": "set-response-datablock", "invoke_id": p.InvokePriority, "block_number": p.BlockNum}, nil
	case gdlms.SetResponseLastDataBlock:
		return tree{"kind": "set-response-last-datablock", "invoke_id": p.InvokePriority, "result": uint8(p.Result),
			"block_number": p.BlockNum}, nil
	case gdlms.SetResponseLastDataBlockWithList:
		return tree{"kind": "set-response-last-datablock-with-list", "invoke_id": p.InvokePriority,
			"results": codes(p.ResultList), "block_number": p.BlockNum}, nil
	case gdlms.SetResponseWithList:
		return tree{"kind": "set-response-with-list", "invoke_id": p.InvokePriority, "results": codes(p.ResultList)}, nil
	case gdlms.ActionRequestNormal:
		var param any
		if p.MethodParam != nil {
			t, err := toTree(p.MethodParam)
			if err != nil {
				return nil, err
			}
			param = t
		}
		return tree{"kind": "action-request-normal", "invoke_id": p.InvokePriority, "method": method(p.MethodInfo),
			"parameters": param}, nil
	case gdlms.ActionRequestNextPBlock:
		return tree{"kind": "action-request-next-pblock", "invoke_id": p.InvokePriority, "block_number": p.BlockNum}, nil
	case gdlms.ActionRequestWithList:
		if len(p.MethodInfoList) != len(p.MethodParamList) {
			return nil, fmt.Errorf("%d methods, %d parameters", len(p.MethodInfoList), len(p.MethodParamList))
		}
		items := []any{}
		for i, m := range p.MethodInfoList {
			v, err := dataTree(p.MethodParamList[i])
			if err != nil {
				return nil, err
			}
			items = append(items, []any{method(m), v})
		}
		return tree{"kind": "action-request-with-list", "invoke_id": p.InvokePriority, "items": items}, nil
	case gdlms.ActionRequestWithFirstPBlock:
		out := blockSA("action-request-with-first-pblock", p.InvokePriority, p.PBlock)
		out["method"] = method(p.MethodInfo)
		return out, nil
	case gdlms.ActionRequestWithListAndFirstPBlock:
		return blockSA("action-request-with-list-and-first-pblock", p.InvokePriority, p.PBlock), nil
	case gdlms.ActionRequestWithPBlock:
		return blockSA("action-request-with-pblock", p.InvokePriority, p.PBlock), nil
	case gdlms.ActionResponseNormal:
		ret, err := actReturn(p.Response)
		return tree{"kind": "action-response-normal", "invoke_id": p.InvokePriority, "result": uint8(p.Response.Result),
			"return_data": ret}, err
	case gdlms.ActionResponseWithPBlock:
		return blockSA("action-response-with-pblock", p.InvokePriority, p.PBlock), nil
	case gdlms.ActionResponseWithList:
		results := []any{}
		for _, r := range p.ResponseList {
			ret, err := actReturn(r)
			if err != nil {
				return nil, err
			}
			results = append(results, []any{uint8(r.Result), ret})
		}
		return tree{"kind": "action-response-with-list", "invoke_id": p.InvokePriority, "results": results}, nil
	case gdlms.ActionResponseNextPBlock:
		return tree{"kind": "action-response-next-pblock", "invoke_id": p.InvokePriority, "block_number": p.BlockNum}, nil
	case gdlms.ConfirmedServiceError:
		return tree{"kind": "confirmed-service-error", "service": uint8(p.ConfirmedServiceError),
			"error_type": uint8(p.ServiceError), "value": p.Value}, nil
	case gdlms.ExceptionResponse:
		return tree{"kind": "exception-response", "state_error": uint8(p.StateError),
			"service_error": uint8(p.ServiceError)}, nil
	case gdlms.DataNotification:
		body, err := dataTree(p.DataValue)
		out := tree{"kind": "data-notification", "long_invoke_id": p.InvokeIDAndPriority, "body": body}
		if p.DateTime == nil {
			// gosem keeps a date-time only as time.Time: compared only when absent.
			out["date_time"] = nil
		}
		return out, err
	case gdlms.EventNotificationRequest:
		v, err := dataTree(p.AttributeValue)
		out := tree{"kind": "event-notification-request", "attribute": attr(p.AttributeInfo), "value": v}
		if p.Time == nil {
			out["time"] = nil
		}
		return out, err
	}
	return nil, errUnsupported(fmt.Sprintf("no mapping for %T", pdu))
}

func codes(list []gdlms.AccessResultTag) []any {
	out := []any{}
	for _, c := range list {
		out = append(out, uint8(c))
	}
	return out
}

func actReturn(r gdlms.ActResponse) (any, error) {
	if r.ReturnParam == nil {
		return nil, nil
	}
	return getDataResult(*r.ReturnParam)
}

// aarq reads an AARQ the way the library's server does (server/aa.go).
func aarq(b []byte) (any, error) {
	items, ok := server.InteropBerItems(b)
	if !ok {
		return nil, errors.New("AARQ does not parse (berItems)")
	}
	ctxName := items[0xA1]
	if len(ctxName) != 9 || ctxName[0] != 0x06 {
		return nil, errors.New("application-context-name is not a 7-octet OID (the server refuses)")
	}
	out := tree{"kind": "aarq", "application_context": ctxName[8], "mechanism": nil,
		"calling_ap_title": nil, "calling_authentication_value": nil}
	if m := items[0x8B]; len(m) == 7 {
		out["mechanism"] = m[6]
	} else if len(m) != 0 {
		return nil, errors.New("mechanism-name is not 7 octets (the server refuses)")
	}
	if v := items[0xA6]; len(v) == 10 && v[0] == 0x04 && v[1] == 0x08 {
		out["calling_ap_title"] = hex.EncodeToString(v[2:])
	}
	if v := items[0xAC]; len(v) >= 2 && v[0] == 0x80 {
		if l, sz := cosem.DecodeLength(v[1:]); l >= 0 && 1+sz+l <= len(v) {
			out["calling_authentication_value"] = hex.EncodeToString(v[1+sz : 1+sz+l])
		}
	}
	if ui := items[0xBE]; len(ui) >= 2 && ui[0] == 0x04 {
		if l, sz := cosem.DecodeLength(ui[1:]); l >= 0 && 1+sz+l <= len(ui) {
			out["user_information"] = hex.EncodeToString(ui[1+sz : 1+sz+l])
		}
	}
	return out, nil
}

func initiateRequest(b []byte) (any, error) {
	r, ok := server.InteropParseInitiate(b)
	if !ok {
		return nil, errors.New("InitiateRequest does not parse (parseInitiate)")
	}
	out := tree{"kind": "initiate-request", "conformance": r.Conformance, "max_receive_pdu_size": r.MaxPDU,
		"dlms_version": r.Version, "response_allowed": !r.Unconfirmed, "dedicated_key": nil}
	if r.DedicatedKey != nil {
		out["dedicated_key"] = hex.EncodeToString(r.DedicatedKey)
	}
	return out, nil
}

// --- push and decrypt ----------------------------------------------------

// suiteFor is the suite a meter with this key is configured for: 2 for a
// 256-bit key, else the suite its security control byte names (suites 0
// and 1 both use AES-128-GCM; the library refuses a mismatch).
func suiteFor(key []byte, sc byte) cosem.Suite {
	if len(key) == 32 {
		return 2
	}
	if sc&0x0F == 1 {
		return 1
	}
	return 0
}

func notificationTree(n *cosem.Notification) (any, error) {
	body, err := toTree(&n.Body)
	if err != nil {
		return nil, err
	}
	out := tree{"long_invoke_id": n.InvokeID, "body": body}
	if n.Time.IsZero() {
		// The library keeps the date-time only as a time.Time; a zero
		// time is "none sent" (or one it could not read).
		out["date_time"] = nil
	}
	return out, nil
}

func opPush(args []string) (any, error) {
	b, err := hexArg(args, 0)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty APDU")
	}
	if b[0] == 0x0F {
		n, err := cosem.DecodeDataNotification(b, time.UTC)
		if err != nil {
			return nil, err
		}
		return notificationTree(n)
	}
	if b[0] != cosem.TagGeneralGlo && b[0] != cosem.TagGeneralDed {
		return nil, errUnsupported(fmt.Sprintf("push tag %#x: the library opens general-glo/-ded pushes only", b[0]))
	}
	ek, err := keyArg(args, 1)
	if err != nil {
		return nil, err
	}
	if len(ek) == 0 {
		return nil, errors.New("ciphered push without a key")
	}
	ak, err := keyArg(args, 2)
	if err != nil {
		return nil, err
	}
	st, content, err := cosem.InteropGeneralGloDed(b)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, errors.New("empty ciphered content")
	}
	src := cosem.PushSource{
		ID:                    "meter",
		Security:              &cosem.Security{Suite: suiteFor(ek, content[0]), Policy: cosem.SecAuthentication | cosem.SecEncryption, Key: ek, AuthKey: ak},
		SystemTitle:           st, // the meter's title as configured
		AcceptUnauthenticated: len(ak) == 0,
		Location:              time.UTC,
	}
	_, n, err := cosem.OpenProtectedPush(b, []cosem.PushSource{src}, nil)
	if err != nil {
		return nil, err
	}
	return notificationTree(n)
}

func opDecrypt(args []string) (any, error) {
	if len(args) != 4 {
		return nil, errors.New("decrypt <ek> <ak> <system-title> <hex>")
	}
	ek, err := keyArg(args, 0)
	if err != nil {
		return nil, err
	}
	ak, err := keyArg(args, 1)
	if err != nil {
		return nil, err
	}
	st, err := keyArg(args, 2)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(args[3])
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && (b[0] == cosem.TagGeneralCiphering || b[0] == cosem.TagGeneralSigning) {
		return nil, errUnsupported("general-ciphering/-signing need the association's key-info state")
	}
	// The encryption key also opens broadcast-key content (PROTOCOL.md).
	plain, err := cosem.InteropOpen(suiteFor(ek, scOf(b)), ek, ek, ak, st, b)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plaintext": hex.EncodeToString(plain)}, nil
}

// scOf is the security control byte of a glo-/ded- or general-glo/-ded APDU.
func scOf(b []byte) byte {
	if len(b) > 0 && (b[0] == cosem.TagGeneralGlo || b[0] == cosem.TagGeneralDed) {
		if _, content, err := cosem.InteropGeneralGloDed(b); err == nil && len(content) > 0 {
			return content[0]
		}
		return 0
	}
	if len(b) > 2 {
		n, sz := cosem.DecodeLength(b[1:])
		if n > 0 && 1+sz < len(b) {
			return b[1+sz]
		}
	}
	return 0
}
