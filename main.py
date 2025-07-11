#!/usr/bin/env python3
"""
Decode an ABI-encoded call to MultiSendCallOnly.multiSend(bytes)
- https://etherscan.io/address/0x40a2accbd92bca938b02010e17a5b8929b49130d#code

Calldata layout
  4  bytes  selector
 32  bytes  head
 32  bytes  length of the bytes arg
  N  bytes  packed transactions payload

Each packed transaction
   1 byte   operation  (0 = CALL, 1 = DELEGATECALL)
  20 bytes  to
  32 bytes  value
  32 bytes  data length
   M bytes  data
"""

# ─────────────────────────────────────────────────────────────────────────────
# Paste the FULL calldata (starting with 0x…) here:
INPUT = ""

# ─────────────────────────────────────────────────────────────────────────────

# --- constants --------------------------------------------------------------
BYTE_OPERATION = 1
BYTES_ADDRESS  = 20
BYTES_UINT256  = 32
FIXED_SECTION  = BYTE_OPERATION + BYTES_ADDRESS + BYTES_UINT256 * 2  # 85 bytes


# --- helpers ----------------------------------------------------------------
def strip_abi_envelope(calldata_hex: str) -> bytes:
    """Return the raw packed-transactions payload (bytes)."""
    if calldata_hex.lower().startswith("0x"):
        calldata_hex = calldata_hex[2:]

    cd = bytes.fromhex(calldata_hex)
    if len(cd) < 4 + 32 + 32:
        raise ValueError("Calldata shorter than ABI envelope (4+32+32 bytes).")

    offset = int.from_bytes(cd[4:36], "big")
    if offset != 32:
        raise ValueError(
            f"Unexpected head offset {offset} (should be 32 for single bytes arg)."
        )

    total_len = int.from_bytes(cd[36:68], "big")
    start, end = 68, 68 + total_len
    if end > len(cd):
        raise ValueError("Declared bytes length exceeds actual calldata size.")

    return cd[start:end]


def decode_packed_transactions(payload: bytes):
    """Yield dicts describing each packed tx. Never abort on op-code."""
    i = 0
    idx = 0
    while i < len(payload):
        if i + FIXED_SECTION > len(payload):
            raise ValueError("Truncated payload while reading header.")

        op = payload[i]
        to_bytes = payload[i + 1 : i + 1 + BYTES_ADDRESS]
        value = int.from_bytes(
            payload[i + 1 + BYTES_ADDRESS : i + 1 + BYTES_ADDRESS + BYTES_UINT256],
            "big",
        )
        data_len = int.from_bytes(
            payload[i + 1 + BYTES_ADDRESS + BYTES_UINT256 : i + FIXED_SECTION], "big"
        )

        data_start = i + FIXED_SECTION
        data_end = data_start + data_len
        if data_end > len(payload):
            raise ValueError(f"Tx #{idx}: data overruns payload.")

        yield {
            "index": idx,
            "op": op,
            "type": "CALL"
            if op == 0
            else "DELEGATECALL"
            if op == 1
            else f"UNKNOWN({op})",
            "to": "0x" + to_bytes.hex(),
            "value": value,
            "data_len": data_len,
            "calldata": "0x" + payload[data_start:data_end].hex(),
        }

        idx += 1
        i = data_end


# --- main -------------------------------------------------------------------
def main() -> None:
    payload = strip_abi_envelope(INPUT)

    any_delegate = False
    for tx in decode_packed_transactions(payload):
        print(f"Transaction {tx['index']}")
        print(f"  Type     : {tx['type']}")
        print(f"  To       : {tx['to']}")
        print(f"  Value    : {tx['value']}")
        print(f"  Data len : {tx['data_len']}")
        print(f"  Calldata : {tx['calldata']}\n")
        if tx["op"] == 1:
            any_delegate = True

    if any_delegate:
        print(
            "⚠️  Warning: one or more DELEGATECALLs detected!"
        )


if __name__ == "__main__":
    main()
