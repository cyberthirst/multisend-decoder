* reads calldata from file specified by `INPUT`
* parses packed transactions from raw payload
  - extracts op type (call or delegatecall), target address, value, calldata length, and calldata
  - doesn't yet decode the sub-calls
