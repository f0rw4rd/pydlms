// Oracle adapter (tests/interop/PROTOCOL.md) around esphome-libs/dlms_parser.
//
// dlms_parser is a push parser: it unwraps the frame (HDLC / M-Bus / raw,
// auto-detected), the APDU (GBT, general-glo/ded ciphering, DATA-NOTIFICATION)
// and then matches A-XDR patterns, emitting one capture per recognised
// COSEM object (OBIS, class id, value, scaler/unit). It produces no data
// tree, so `push` answers with that capture list instead of the protocol's
// {long_invoke_id, date_time, body}; tests/interop/test_push_parsers.py maps
// pydlms's PushDecoder records onto the same shape.
//
// Ops:
//   hello
//   push <hex> [<ek>|- [<ak>|-]]   frame or APDU -> {"axdr", "captures", "logs"}
//   frame <hex> <ek>|- <ak>|- crc|nocrc   same, with the CRC switch
// Everything else answers unsupported.

#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "dlms_parser/apdu_handler.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"
#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/hdlc_decoder.h"
#include "dlms_parser/mbus_decoder.h"

namespace {

const char* type_name(dlms_parser::DlmsDataType t) {
  using T = dlms_parser::DlmsDataType;
  switch (t) {
    case T::NONE: return "null-data";
    case T::ARRAY: return "array";
    case T::STRUCTURE: return "structure";
    case T::BOOLEAN: return "boolean";
    case T::BIT_STRING: return "bit-string";
    case T::INT32: return "double-long";
    case T::UINT32: return "double-long-unsigned";
    case T::OCTET_STRING: return "octet-string";
    case T::STRING: return "visible-string";
    case T::STRING_UTF8: return "utf8-string";
    case T::BINARY_CODED_DECIMAL: return "bcd";
    case T::INT8: return "integer";
    case T::INT16: return "long";
    case T::UINT8: return "unsigned";
    case T::UINT16: return "long-unsigned";
    case T::COMPACT_ARRAY: return "compact-array";
    case T::INT64: return "long64";
    case T::UINT64: return "long64-unsigned";
    case T::ENUM: return "enum";
    case T::FLOAT32: return "float32";
    case T::FLOAT64: return "float64";
    case T::DATETIME: return "date-time";
    case T::DATE: return "date";
    case T::TIME: return "time";
  }
  return "unknown";
}

std::string hex(std::span<const uint8_t> data) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t b : data) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0x0F]);
  }
  return out;
}

std::string json_string(std::string_view s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      default:
        if (c < 0x20 || c >= 0x7F) {
          char buf[8];
          snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  return out + "\"";
}

std::optional<std::vector<uint8_t>> unhex(const std::string& s) {
  if (s.size() % 2) return std::nullopt;
  std::vector<uint8_t> out;
  for (size_t i = 0; i < s.size(); i += 2) {
    unsigned v;
    if (sscanf(s.c_str() + i, "%2x", &v) != 1) return std::nullopt;
    out.push_back(static_cast<uint8_t>(v));
  }
  return out;
}

struct Run {
  std::vector<std::string> logs;     // warnings and errors, verbatim
  std::vector<std::string> patterns; // "Pattern '<name>' matched" in order
  std::vector<std::string> captures; // JSON objects
};

Run* current = nullptr;

void log_sink(dlms_parser::LogLevel level, const char* fmt, va_list args) {
  if (!current) return;
  char buf[512];
  vsnprintf(buf, sizeof buf, fmt, args);
  std::string text(buf);
  if (text.rfind("Pattern '", 0) == 0) {
    auto end = text.find('\'', 9);
    current->patterns.push_back(text.substr(9, end - 9));
  }
  if (level == dlms_parser::LogLevel::WARNING || level == dlms_parser::LogLevel::ERROR) {
    current->logs.push_back(text);
  }
}

std::string capture_json(const dlms_parser::AxdrCapture& c, const std::string& pattern) {
  char obis_buf[32];
  std::string out = "{\"obis\":\"" + std::string(c.obis.to_string(obis_buf)) + "\"";
  out += ",\"class_id\":" + std::to_string(c.class_id);
  out += ",\"type\":\"" + std::string(type_name(c.value_type)) + "\"";
  out += ",\"value\":\"" + hex(c.value) + "\"";
  if (c.has_scaler_unit) {
    out += ",\"scaler\":" + std::to_string(c.scaler);
    out += ",\"unit\":" + std::to_string(c.unit_enum);
  }
  out += ",\"numeric\":" + std::string(c.is_numeric() ? "true" : "false");
  if (c.is_numeric()) {
    char num[64];
    snprintf(num, sizeof num, "%.9g", static_cast<double>(c.value_as_float_with_scaler_applied()));
    std::string n(num);
    out += ",\"number\":" + ((n == "nan" || n == "-nan" || n == "inf" || n == "-inf") ? "null" : n);
  }
  std::array<char, 128> text_buf{};
  out += ",\"text\":" + json_string(c.value_as_string(text_buf));
  out += ",\"pattern\":" + json_string(pattern);
  return out + "}";
}

// The A-XDR payload dlms_parser hands to its pattern matcher, recomputed
// with its own public frame/APDU functions on a copy of the input.
std::string axdr_of(std::vector<uint8_t> buf, dlms_parser::Aes128GcmDecryptor* decryptor, bool skip_crc) {
  std::span<uint8_t> view(buf);
  if (dlms_parser::is_mbus_short_frame(view)) view = view.subspan(5);
  if (view.empty()) return "";
  std::span<uint8_t> decoded = view;
  if (view[0] == 0x7E) decoded = dlms_parser::decode_hdlc_frames_in_place(view, skip_crc);
  else if (view[0] == 0x68) decoded = dlms_parser::decode_mbus_frames_in_place(view, skip_crc);
  if (decoded.empty()) return "";
  return hex(dlms_parser::parse_apdu_in_place(decoded, decryptor));
}

std::string run(const std::vector<uint8_t>& input, const std::string& ek, const std::string& ak, bool skip_crc) {
  dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
  if (!ek.empty() && ek != "-") {
    auto key = dlms_parser::Aes128GcmDecryptionKey::from_hex(ek);
    if (!key) return R"({"ok":false,"error":"bad encryption key"})";
    decryptor.set_decryption_key(*key);
  }
  if (!ak.empty() && ak != "-") {
    auto key = dlms_parser::Aes128GcmAuthenticationKey::from_hex(ak);
    if (!key) return R"({"ok":false,"error":"bad authentication key"})";
    decryptor.set_authentication_key(*key);
  }

  Run state;
  current = &state;
  const std::string axdr = axdr_of(input, &decryptor, skip_crc);
  state.logs.clear();
  state.patterns.clear();

  std::vector<std::pair<std::string, dlms_parser::AxdrCapture>> raw;
  dlms_parser::DlmsParser parser(
      [&](const dlms_parser::AxdrCapture& c) {
        std::string pattern = state.patterns.empty() ? "" : state.patterns.back();
        state.captures.push_back(capture_json(c, pattern));
      },
      &decryptor);
  parser.load_default_patterns();
  parser.set_skip_crc_check(skip_crc);
  std::vector<uint8_t> work = input;
  auto result = parser.parse(work);
  current = nullptr;

  std::string logs = "[";
  for (size_t i = 0; i < state.logs.size(); ++i) logs += (i ? "," : "") + json_string(state.logs[i]);
  logs += "]";
  if (result.count == 0) {
    std::string error = state.logs.empty() ? "no COSEM objects found" : state.logs.front();
    return "{\"ok\":false,\"error\":" + json_string(error) + ",\"logs\":" + logs + "}";
  }
  std::string caps = "[";
  for (size_t i = 0; i < state.captures.size(); ++i) caps += (i ? "," : "") + state.captures[i];
  caps += "]";
  return "{\"ok\":true,\"result\":{\"axdr\":\"" + axdr + "\",\"count\":" + std::to_string(result.count) +
         ",\"captures\":" + caps + ",\"logs\":" + logs + "}}";
}

}  // namespace

int main() {
  dlms_parser::Logger::set_log_function(log_sink);
  std::string line;
  while (std::getline(std::cin, line)) {
    std::vector<std::string> args;
    size_t pos = 0;
    while (pos < line.size()) {
      size_t end = line.find(' ', pos);
      if (end == std::string::npos) end = line.size();
      if (end > pos) args.push_back(line.substr(pos, end - pos));
      pos = end + 1;
    }
    std::string reply;
    const std::string op = args.empty() ? "" : args[0];
    if (op == "hello") {
      reply = R"J({"ok":true,"library":"esphome-libs/dlms_parser","version":"2.2.0 (a80697723e9c)","ops":["push","frame"]})J";
    } else if ((op == "push" && args.size() >= 2) || (op == "frame" && args.size() == 5)) {
      auto input = unhex(args[1]);
      if (!input || input->empty()) {
        reply = R"({"ok":false,"error":"bad hex"})";
      } else {
        const std::string ek = args.size() > 2 ? args[2] : "";
        const std::string ak = args.size() > 3 ? args[3] : "";
        const bool skip_crc = op == "frame" && args[4] == "nocrc";
        reply = run(*input, ek, ak, skip_crc);
      }
    } else {
      reply = "{\"ok\":false,\"unsupported\":true,\"error\":" + json_string("op " + op + " not offered by dlms_parser") + "}";
    }
    std::cout << reply << '\n' << std::flush;
  }
  return 0;
}
