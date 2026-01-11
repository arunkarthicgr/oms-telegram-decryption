#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstdint>
#include <algorithm>

#include <openssl/evp.h>

using namespace std;

// Utils


static vector<uint8_t> hex_to_bytes(string hex) {
    string clean;
    for (char c : hex) {
        if (!isspace((unsigned char)c))
            clean.push_back((char)tolower(c));
    }
    if (clean.size() % 2 != 0) throw runtime_error("Hex length must be even");

    vector<uint8_t> out;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        out.push_back((uint8_t)strtoul(clean.substr(i, 2).c_str(), nullptr, 16));
    }
    return out;
}

static string hex2(uint8_t b) {
    stringstream ss;
    ss << hex << setw(2) << setfill('0') << (int)b;
    return ss.str();
}

static void print_hex(const string& label, const vector<uint8_t>& data, size_t maxBytes = 0) {
    cout << label << " (" << data.size() << " bytes): ";
    size_t n = data.size();
    if (maxBytes > 0) n = min(n, maxBytes);

    for (size_t i = 0; i < n; i++)
        cout << hex << setw(2) << setfill('0') << (int)data[i];

    if (maxBytes > 0 && data.size() > maxBytes) cout << "...";
    cout << dec << "\n";
}

static uint64_t read_le_uint64(const uint8_t* p, int len) {
    uint64_t v = 0;
    for (int i = 0; i < len; i++)
        v |= ((uint64_t)p[i] << (8ULL * i));
    return v;
}

// AES-128-CBC Decrypt (EVP) - OpenSSL 3+ safe


static vector<uint8_t> aes128_cbc_decrypt_evp(
    const vector<uint8_t>& key,
    const vector<uint8_t>& iv,
    const vector<uint8_t>& ciphertext
) {
    if (key.size() != 16) throw runtime_error("AES-128 key must be 16 bytes");
    if (iv.size() != 16) throw runtime_error("IV must be 16 bytes");
    if (ciphertext.empty()) throw runtime_error("Ciphertext empty");
    if (ciphertext.size() % 16 != 0) throw runtime_error("CBC ciphertext must be multiple of 16");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

    vector<uint8_t> plaintext(ciphertext.size() + 16);
    int outLen1 = 0, outLen2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex failed");
    }

    // OMS telegram: no PKCS padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1,
                         ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptUpdate failed");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptFinal_ex failed (wrong key/iv/ciphertext)");
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen1 + outLen2);
    return plaintext;
}

static vector<uint8_t> build_iv_mode5(uint8_t accessNo) {
    // OMS Mode 5 IV = AccessNo repeated 16 bytes (common implementation)
    return vector<uint8_t>(16, accessNo);
}


// Header decode: Meter ID, Manufacturer, Medium


struct MeterInfo {
    string manufacturer;
    uint32_t meterId = 0;
    string medium;
};

static string decode_manufacturer(uint16_t mfield) {
    // EN13757: 3 letters packed in 5-bit groups
    char m1 = char(((mfield >> 10) & 0x1F) + 'A' - 1);
    char m2 = char(((mfield >> 5)  & 0x1F) + 'A' - 1);
    char m3 = char(((mfield >> 0)  & 0x1F) + 'A' - 1);
    string s;
    s.push_back(m1); s.push_back(m2); s.push_back(m3);
    return s;
}

static string decode_medium(uint8_t dllType) {
    // minimal map for common meters
    switch (dllType) {
        case 0x07: return "water";
        case 0x06: return "heat";
        case 0x02: return "electricity";
        case 0x03: return "gas";
        default:   return "unknown";
    }
}

static MeterInfo extract_meter_info(const vector<uint8_t>& telegram) {
    if (telegram.size() < 10) throw runtime_error("Telegram too short for header fields");

 
    uint16_t mfct = (uint16_t)telegram[2] | ((uint16_t)telegram[3] << 8);
    uint32_t id   = (uint32_t)telegram[4]
                  | ((uint32_t)telegram[5] << 8)
                  | ((uint32_t)telegram[6] << 16)
                  | ((uint32_t)telegram[7] << 24);
    uint8_t type  = telegram[9];

    MeterInfo info;
    info.manufacturer = decode_manufacturer(mfct);
    info.meterId = id;
    info.medium = decode_medium(type);
    return info;
}


//  to get CI and Access Number


struct ParsedHeader {
    uint8_t ci = 0;
    size_t ciOffset = 0;
    size_t tplOffset = 0;
    uint8_t accessNo = 0;
};

static ParsedHeader parse_ci_tpl(const vector<uint8_t>& telegram) {
    if (telegram.size() < 20) throw runtime_error("Telegram too short");

    vector<uint8_t> cis = {0x8C, 0x8D, 0x8E};
    ParsedHeader p{};
    bool found = false;

    for (size_t i = 0; i < min<size_t>(telegram.size(), 60); i++) {
        if (find(cis.begin(), cis.end(), telegram[i]) != cis.end()) {
            p.ci = telegram[i];
            p.ciOffset = i;
            found = true;
            break;
        }
    }
    if (!found) throw runtime_error("CI not found (0x8C/0x8D/0x8E)");

    p.tplOffset = p.ciOffset + 1;
    if (p.tplOffset >= telegram.size()) throw runtime_error("TPL offset out of range");

   
    if (telegram[p.ciOffset] == 0x8C && p.ciOffset + 4 < telegram.size()) {
        // TPL access field
        p.accessNo = telegram[p.ciOffset + 4];
        p.tplOffset = p.ciOffset + 3; 
    } else {
        p.accessNo = telegram[p.tplOffset];
    }

    return p;
}


// DIF/VIF Parsing helpers


static int dif_data_len_basic(uint8_t dif) {
    int l = dif & 0x0F;
    switch (l) {
        case 0: return 0;
        case 1: return 1;
        case 2: return 2;
        case 3: return 3;
        case 4: return 4;
        case 5: return 4;
        case 6: return 6;
        case 7: return 8;
        default: return -1;
    }
}

static bool is_valid_dif(uint8_t dif) {
    int l = dif & 0x0F;
    return (l <= 7);
}

static size_t skip_extensions(const vector<uint8_t>& buf, size_t i) {
    while (i < buf.size()) {
        uint8_t b = buf[i++];
        if ((b & 0x80) == 0) break;
    }
    return i;
}

static bool parse_one_record(const vector<uint8_t>& plain, size_t& i) {
    if (i >= plain.size()) return false;
    uint8_t dif = plain[i++];

    if (dif == 0x2F) return true;
    if (!is_valid_dif(dif)) return false;

    int len = dif_data_len_basic(dif);
    if (len < 0) return false;

    if (dif & 0x80) {
        if (i >= plain.size()) return false;
        i = skip_extensions(plain, i);
    }

    if (i >= plain.size()) return false;
    uint8_t vif = plain[i++];

    if (vif & 0x80) {
        if (i >= plain.size()) return false;
        i = skip_extensions(plain, i);
    }

    if (i + (size_t)len > plain.size()) return false;
    i += len;
    return true;
}

static int score_records(const vector<uint8_t>& plain, size_t start, int maxRecords = 25) {
    size_t i = start;
    int ok = 0;
    for (int r = 0; r < maxRecords; r++) {
        size_t before = i;
        if (!parse_one_record(plain, i)) break;
        ok++;

        if (plain[before] == 0x2F && ok <= 2) return 0;
    }
    return ok;
}

static size_t find_best_record_start(const vector<uint8_t>& plain) {
    int best = -1;
    size_t bestStart = 0;

    for (size_t start = 0; start + 8 < plain.size(); start++) {
        if (!is_valid_dif(plain[start]) && plain[start] != 0x2F) continue;

        int sc = score_records(plain, start, 30);
        if (sc > best) {
            best = sc;
            bestStart = start;
        }
    }
    return bestStart;
}

static string vif_unit(uint8_t vif) {
    uint8_t x = vif & 0x7F;
    if (x == 0x06) return "Energy [Wh]";
    if (x == 0x07) return "Energy [kWh]";
    if (x == 0x13) return "Volume [m^3]";
    if (x == 0x5B) return "Flow temperature [°C]";
    if (x == 0x5C) return "Return temperature [°C]";
    return "Unknown";
}

static bool is_invalid_value(uint64_t value, int lenBytes) {
    if (lenBytes == 4 && value == 0xFFFFFFFFULL) return true;
    if (lenBytes == 2 && value == 0xFFFFULL) return true;
    if (lenBytes == 1 && value == 0xFFULL) return true;
    return false;
}

static void decode_records_and_print(const vector<uint8_t>& plain) {
    size_t start = find_best_record_start(plain);
    int score = score_records(plain, start, 50);

    cout << "\n==============================\n";
    cout << "Decoded Records (DIF/VIF)\n";
    cout << "==============================\n";
    cout << "Record start offset = " << start << "\n";
    cout << "Record score        = " << score << "\n\n";

    size_t i = start;
    int rec = 1;

    while (i < plain.size()) {
        size_t recordStart = i;

        uint8_t dif = plain[i++];
        if (dif == 0x2F) {
            cout << "[End marker 0x2F]\n";
            break;
        }

        if (!is_valid_dif(dif)) {
            cout << "Stop: Invalid DIF=0x" << hex2(dif) << " at offset " << recordStart << "\n";
            break;
        }

        int len = dif_data_len_basic(dif);
        if (len < 0) break;

        if (dif & 0x80) i = skip_extensions(plain, i);

        if (i >= plain.size()) break;
        uint8_t vif = plain[i++];

        if (vif & 0x80) i = skip_extensions(plain, i);

        if (i + (size_t)len > plain.size()) break;

        uint64_t value = read_le_uint64(&plain[i], len);
        i += len;

        cout << "Record " << setw(2) << rec++
             << " | DIF=0x" << hex2(dif)
             << " VIF=0x" << hex2(vif)
             << " | " << vif_unit(vif)
             << " | Value: ";

        if (is_invalid_value(value, len)) cout << "N/A";
        else cout << value;

        cout << " (len=" << len << ")\n";
    }
}


// Main


int main() {
    try {
        string key_hex = "4255794d3dccfd46953146e701b7db68";

        string msg_hex =
            "a144c5142785895070078c20607a9d00902537ca231fa2da5889be8df367"
            "3ec136aebfb80d4ce395ba98f6b3844a115e4be1b1c9f0a2d5ffbb92906aa388deaa"
            "82c929310e9e5c4c0922a784df89cf0ded833be8da996eb5885409b6c9867978dea"
            "24001d68c603408d758a1e2b9c42ebad86a9b9d287880083bb0702850574d7b51"
            "e9c209ed68e0374e9b01febfd92b4cb9410fdea7fb526b742dc9a8d0682653";

        vector<uint8_t> key = hex_to_bytes(key_hex);
        vector<uint8_t> telegram = hex_to_bytes(msg_hex);

        cout << "=====================================\n";
        cout << " OMS Mode 5 Final Decoder (C++)\n";
        cout << "=====================================\n\n";

        print_hex("Key", key);
        print_hex("Telegram", telegram, 90);

        // ----- NEW: Print Meter Info -----
        MeterInfo mi = extract_meter_info(telegram);
        cout << "\n--- Meter Info ---\n";
        cout << "Meter ID     : " << mi.meterId << "\n";
        cout << "Manufacturer : " << mi.manufacturer << "\n";
        cout << "Medium       : " << mi.medium << "\n";

        // Parse header fields for decrypt
        ParsedHeader ph = parse_ci_tpl(telegram);

        cout << "\n--- Header ---\n";
        cout << "CI        : 0x" << hex2(ph.ci) << " at offset " << ph.ciOffset << "\n";
        cout << "TPL offset : " << ph.tplOffset << "\n";
        cout << "Access No  : 0x" << hex2(ph.accessNo) << " (" << (int)ph.accessNo << ")\n";

        vector<uint8_t> iv = build_iv_mode5(ph.accessNo);
        print_hex("IV", iv);

        // Search offsets and SCORE candidates
        size_t searchStart = ph.tplOffset;
        size_t searchEnd = min(telegram.size(), ph.tplOffset + 60);

        cout << "\n--- Searching encrypted payload offset (scored) ---\n";

        int bestScore = -1;
        size_t bestOff = 0;
        vector<uint8_t> bestPlain;

        for (size_t off = searchStart; off < searchEnd; off++) {
            size_t remain = telegram.size() - off;
            size_t aligned = (remain / 16) * 16;
            if (aligned < 32) continue;

            vector<uint8_t> ct(telegram.begin() + off, telegram.begin() + off + aligned);

            vector<uint8_t> plain;
            try {
                plain = aes128_cbc_decrypt_evp(key, iv, ct);
            } catch (...) {
                continue;
            }

            size_t recordStart = find_best_record_start(plain);
            int score = score_records(plain, recordStart, 25);

            cout << "Offset=" << setw(2) << off
                 << " aligned=" << setw(3) << aligned
                 << " recordStart=" << setw(3) << recordStart
                 << " score=" << score << "\n";

            if (score > bestScore) {
                bestScore = score;
                bestOff = off;
                bestPlain = plain;
            }
        }

        if (bestScore <= 0) {
            cout << "\n No valid candidate offset found.\n";
            return 1;
        }

        cout << "\n BEST candidate:\n";
        cout << "Encrypted payload offset = " << bestOff << "\n";
        cout << "Best score               = " << bestScore << "\n";

        print_hex("Decrypted payload", bestPlain, 200);

        decode_records_and_print(bestPlain);

        cout << "\n Done.\n";
        return 0;
    }
    catch (const exception& e) {
        cerr << "\n ERROR: " << e.what() << "\n";
        return 1;
    }
}
