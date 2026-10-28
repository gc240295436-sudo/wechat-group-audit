# Source and license provenance

WeChat Group Audit is a new, independently implemented project for local friend/group analysis. It does not include source files, modules, or private data from the restricted `mcncarl/yichen-skills` collection. That collection was the starting point for the earlier local experiment; its source is not redistributed here.

The domain model, set analysis, JSON/SQLite readers, WAL transaction replay, SQLCipher page verification/decryption, Windows API wrappers, CLI, reports, examples, and tests in this repository were written for this project. The public format/API references used are listed below. The only vendored code is the explicitly identified MIT selection.

## Vendored MIT selection

- Project: [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool).
- Commit: `79f1b5b92e12c66aa281b4a60a3c478b5f547dfa`.
- Source: [`wcdb_key_tool_windows.py`](https://github.com/TANGandXUE/wcdb-key-tool/blob/79f1b5b92e12c66aa281b4a60a3c478b5f547dfa/wcdb_key_tool_windows.py).
- Original file SHA-256: `9de22ccc5070bfc5325ece1bdf4da8ca537eea594b821fc2acd46a62c0e41958`.
- Copyright: 2025 CloudDreamAI / TANGandXUE; MIT license, preserved in [LICENSES/wcdb-key-tool-MIT.txt](LICENSES/wcdb-key-tool-MIT.txt).
- Destination: `src/wechat_group_audit/_wcdb_scan.py`.
- Included: `KEY_SZ`, the five `WINDOWS_CONFIG_*` / address constants used by the object reader, and eight pure helper/object-traversal functions from `_xor_repeat` through `_scan_windows_v411_config_cipher`. Function bodies are unchanged; imports are reduced and the page-key verifier is bound to this project's implementation.
- Excluded: upstream CLI, process access implementation, debugger/CDB paths, experimental capture, passphrase/key persistence, database collection, and file export code.

Only read-only callbacks are supplied to the selected traversal functions. Every candidate must match the selected contact database's page HMAC. Successful matching does not expand access to other accounts or databases.

## Public technical references

- [SQLCipher design](https://www.zetetic.net/sqlcipher/design/): page encryption, authentication, raw keys, salt, and key separation.
- [SQLite database and WAL formats](https://sqlite.org/fileformat2.html): headers, committed transaction markers, checksums, reset generations, and database-size changes.
- [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex), [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust): Windows read access and executable identity verification.
- [Restart Manager](https://learn.microsoft.com/en-us/windows/win32/rstmgr/restart-manager-reference): file-holder discovery. No restart/shutdown API is used.
- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html): immutable read-only connections and in-memory deserialize.

`pycryptodome==3.23.0` is an optional installed dependency for AES, not vendored source. Its own distribution retains its licenses. All checked-in example data and test identities are synthetic.
