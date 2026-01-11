# OMS Mode 5 W-MBus Telegram Decryption

This project demonstrates how to decrypt and decode an OMS Mode 5 encrypted Wireless M-Bus (W-MBus) telegram using AES-128-CBC and extract human-readable meter data.
--
# 1. Telegram Structure

An OMS Mode 5 W-MBus telegram consists of a plaintext header and an encrypted payload.

Telegram Layout
| Offset | Length | Field | Description |
|---|---|---|---|
| 0 | 1 | L-Field | Telegram length |
| 1 | 1 | C-Field | Control field |
| 2–3 | 2 | Manufacturer ID | 3-letter manufacturer code (EN 13757) |
| 4–7 | 4 | Meter ID | Unique meter serial number |
| 8 | 1 | Version | Meter version |
| 9 | 1 | Medium | Meter type (water, gas, etc.) |
| 10 | 1 | CI Field | Control Information (0x8C = encrypted OMS) |
| 11–? | – | Transport Layer | Contains Access Number |
| ? | – | Encrypted Payload | AES-128-CBC encrypted meter data |

Medium Values
# Value	Medium
| Value | Medium      |
| ----: | ----------- |
| 0x02  | Electricity |
| 0x03  | Gas         |
| 0x06  | Heat        |
| 0x07  | Water       |


# 2. Decryption Process

OMS Mode 5 uses AES-128 in CBC mode with no padding.
--
# High-Level Steps

Convert AES key from hex to bytes

Parse telegram header

Extract Access Number from the Transport Layer

Build IV (Access Number repeated 16 times)

Locate encrypted payload (16-byte aligned)

Decrypt payload using AES-128-CBC

Validate decrypted data using DIF/VIF record parsing

Cryptography Details
| Parameter | Value                    |
| --------- | ------------------------ |
| Cipher    | AES-128                  |
| Mode      | CBC                      |
| Padding   | None                     |
| IV        | Access Number × 16 bytes |


# Tools / Libraries Used

C++17

OpenSSL EVP API

OMS Volume 2 specification

# 3. Decoded Meter Information

Extracted from the plaintext header.

| Field        | Value          |
| ------------ | -------------- |
| Meter ID     | **1351189799** |
| Manufacturer | **EFE**        |
| Medium       | **Water**      |


# 4. Decoded Measurement Records

Extracted from the decrypted payload using DIF/VIF parsing.

DIF/VIF Output Table
Record	DIF	VIF	Measurement	Value
| S.No | DIF  | VIF  | Measurement Type | Value               |
| ---: | ---- | ---- | ---------------- | ------------------- |
| 1    | 0x77 | 0xA6 | Unknown          | 1261028806313377200 |
| 2    | 0x00 | 0x00 | Unknown          | 0                   |
| 3    | 0x01 | 0xFD | Unknown          | 0                   |
| 4    | 0x42 | 0x6C | Unknown          | N/A                 |
| 5    | 0x44 | 0x13 | Volume [m³]      | 0                   |
| 6    | 0x44 | 0x93 | Volume [m³]      | 0                   |
| 7    | 0x84 | 0x13 | Volume [m³]      | 0                   |
| 8    | 0xC4 | 0x13 | Volume [m³]      | 0                   |
| 9    | 0x84 | 0x13 | Volume [m³]      | 18                  |
| 10   | 0xC4 | 0x13 | Volume [m³]      | 0                   |
| 11   | 0x84 | 0x13 | Volume [m³]      | N/A                 |
| 12   | 0xC4 | 0x13 | Volume [m³]      | N/A                 |
| 13   | 0x84 | 0x13 | Volume [m³]      | 4151779436          |



Primary Consumption Value:

Water Volume = 18 m³


Invalid values (0xFFFFFFFF) are correctly interpreted as not available.

# 5. Build and Run
Compile
g++ -std=c++17 decrypt_oms.cpp -o decrypt_oms -lssl -lcrypto

Run
./decrypt_oms
# 6. output screenshots
<img width="940" height="979" alt="image" src="https://github.com/user-attachments/assets/07ced38c-7b35-4ca5-9b3e-2db64a383117" />
<img width="940" height="986" alt="image" src="https://github.com/user-attachments/assets/1e06632c-24ea-49b9-8a3c-fc24e7b91289" />


