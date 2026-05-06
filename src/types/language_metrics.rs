//! Language-specific metrics for source code analysis

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_u32, is_zero_u64};

// =============================================================================
// LANGUAGE-SPECIFIC METRICS
// =============================================================================

/// Python-specific metrics for obfuscation/malware detection
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PythonMetrics {
    // === Dynamic Execution ===
    /// Number of eval() calls in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// Number of exec() calls in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Number of compile() calls in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compile_count: u32,
    /// Number of __import__() dynamic import calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_import_count: u32,
    /// Number of importlib module usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub importlib_count: u32,
    /// getattr/setattr/delattr calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub attr_manipulation_count: u32,

    // === Obfuscation Patterns ===
    /// Number of chr() character-code calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_calls: u32,
    /// Number of ord() character-code calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ord_calls: u32,
    /// Number of lambda expressions in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lambda_count: u32,
    /// Nested lambdas (lambda inside lambda)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_lambda_count: u32,
    /// Maximum comprehension nesting depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comprehension_depth_max: u32,
    /// Walrus operator usage (:=)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub walrus_operator_count: u32,

    // === Reflection/Introspection ===
    /// globals()/locals() access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub globals_locals_access: u32,
    /// Number of __builtins__ namespace accesses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub builtins_access: u32,
    /// type() calls (metaclass tricks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_calls: u32,
    /// Number of __class__ attribute accesses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_access: u32,
    /// Number of vars() introspection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_calls: u32,
    /// Number of dir() introspection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dir_calls: u32,

    // === Serialization (RCE vectors) ===
    /// Number of pickle module usages (RCE vector)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pickle_usage: u32,
    /// Number of marshal module usages (RCE vector)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,
    /// Number of unsafe yaml.load() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_unsafe: u32,
    /// Number of shelve module usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shelve_usage: u32,

    // === Decorators ===
    /// Total number of decorator applications
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decorator_count: u32,
    /// Max decorators stacked on one function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stacked_decorators_max: u32,

    // === Magic Methods ===
    /// Dunder method definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_method_count: u32,
    /// __getattribute__ override
    #[serde(default, skip_serializing_if = "is_false")]
    pub getattribute_override: bool,
    /// Whether __new__ is overridden in the source
    #[serde(default, skip_serializing_if = "is_false")]
    pub new_override: bool,
    /// Descriptor protocol (__get__, __set__)
    #[serde(default, skip_serializing_if = "is_false")]
    pub descriptor_protocol: bool,

    // === Encoding/Decoding ===
    /// Number of base64 module encode/decode calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_calls: u32,
    /// Number of codecs module encode/decode calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub codecs_calls: u32,
    /// Number of zlib or gzip compression calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compression_calls: u32,
    /// Whether rot13 encoding is used in the source
    #[serde(default, skip_serializing_if = "is_false")]
    pub rot13_usage: bool,

    // === Control Flow ===
    /// Number of try/except exception-handling blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub try_except_count: u32,
    /// Number of bare except clauses catching everything
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bare_except_count: u32,
    /// except Exception (too broad)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub broad_except_count: u32,
    /// Maximum control-flow nesting depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,

    // === Additional Structural Metrics ===
    /// Number of vars() calls for locals inspection
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_access: u32,
    /// type() manipulation (3-arg form)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_manipulation: u32,
    /// Number of __code__ bytecode object accesses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_object_access: u32,
    /// Frame access (sys._getframe, inspect.currentframe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub frame_access: u32,
    /// Number of class definitions in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Number of metaclass customizations in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub metaclass_usage: u32,
    /// Number of with-statement context manager uses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement_count: u32,
    /// Number of assert statements in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_count: u32,
}

/// JavaScript/TypeScript metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JavaScriptMetrics {
    // === Dynamic Execution ===
    /// Number of eval() dynamic execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// new Function() constructor
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_constructor: u32,
    /// setTimeout with string argument
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub settimeout_string: u32,
    /// setInterval with string argument
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setinterval_string: u32,
    /// Number of document.write injection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub document_write: u32,

    // === Obfuscation Patterns ===
    /// String.fromCharCode calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub from_char_code_count: u32,
    /// Number of charCodeAt character access calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_code_at_count: u32,
    /// Array.join for string building
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_strings: u32,
    /// split().reverse().join() patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub split_reverse_join: u32,
    /// Number of chained .replace() call patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_chain_count: u32,
    /// Computed property access obj[var]
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_property_access: u32,

    // === Encoding ===
    /// Number of atob and btoa base64 call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub atob_btoa_count: u32,
    /// Number of escape and unescape call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub escape_unescape: u32,
    /// Number of decodeURIComponent call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decode_uri_component: u32,

    // === Suspicious Constructs ===
    /// with statements (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement: u32,
    /// Number of debugger statements in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debugger_statements: u32,
    /// arguments.caller/callee access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub caller_callee_access: u32,
    /// Prototype pollution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub prototype_pollution_patterns: u32,
    /// Number of __proto__ prototype access sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proto_access: u32,

    // === Functions & Closures ===
    /// IIFE count (function(){})()
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub iife_count: u32,
    /// Maximum nested IIFE depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_iife_depth: u32,
    /// Number of arrow function expressions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arrow_function_count: u32,
    /// Deepest nested closure depth in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub closure_depth_max: u32,

    // === Array/Object Patterns ===
    /// Large array literals (>100 elements)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_array_literals: u32,
    /// Computed object keys {[expr]: val}
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_key_count: u32,
    /// Excessive spread operator usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spread_count: u32,

    // === DOM Manipulation ===
    /// Number of innerHTML property write sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub innerhtml_writes: u32,
    /// Number of dynamic script element creations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_element_creation: u32,
    /// Event handler strings (onclick="...")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub event_handler_strings: u32,
    /// Number of XHR and fetch network request sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub network_requests: u32,
}

/// Shell script metrics (bash/sh/zsh)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ShellMetrics {
    // === Command Execution ===
    /// Number of eval dynamic execution call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// Number of source and . file sourcing calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub source_count: u32,
    /// Number of exec process replacement commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Number of bash -c inline script executions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bash_c_count: u32,
    /// Number of xargs argument-expansion usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xargs_count: u32,

    // === Network Operations ===
    /// Number of curl and wget download command calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_wget_count: u32,
    /// Number of nc and netcat network tool uses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nc_netcat_count: u32,
    /// /dev/tcp or /dev/udp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_tcp_count: u32,
    /// DNS exfiltration patterns (dig, nslookup abuse)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dns_exfil_patterns: u32,
    /// Number of ssh and scp remote access calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ssh_scp_count: u32,

    // === Encoding/Decoding ===
    /// Number of base64 decode command usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// Number of xxd hex dump command usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxd_count: u32,
    /// Number of printf calls with hex escape codes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub printf_hex_count: u32,
    /// Number of openssl enc encryption calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub openssl_enc_count: u32,
    /// Number of gzip and gunzip call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_count: u32,

    // === Pipes & Redirection ===
    /// Total number of pipe operators in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_count: u32,
    /// Deepest nested pipeline chain in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_depth_max: u32,
    /// Number of here-document heredoc blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub here_doc_count: u32,
    /// Process substitution <() >()
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_substitution: u32,
    /// File descriptor redirection
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fd_redirection: u32,

    // === Anti-Forensics ===
    /// History manipulation (unset HISTFILE, etc.)
    #[serde(default, skip_serializing_if = "is_false")]
    pub history_manipulation: bool,
    /// Number of background job & operators used
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub background_jobs: u32,
    /// Number of nohup and disown detach calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nohup_disown_count: u32,
    /// Number of cron and at scheduler manipulations
    #[serde(default, skip_serializing_if = "is_false")]
    pub cron_at_manipulation: bool,
    /// Number of chmod +x permission set calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chmod_x_count: u32,
    /// Number of shred and rm -rf destructive calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub secure_delete_count: u32,

    // === Variable Tricks ===
    /// Indirect variable expansion ${!var}
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_vars: u32,
    /// eval with variable expansion
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_expansion: u32,
    /// Number of IFS field separator manipulations
    #[serde(default, skip_serializing_if = "is_false")]
    pub ifs_manipulation: bool,
    /// Number of PATH environment variable changes
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_manipulation: bool,

    // === Timing/Evasion ===
    /// Number of sleep delay command usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sleep_count: u32,
    /// Number of timeout command usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timeout_count: u32,
    /// trap commands (signal handling)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trap_count: u32,

    // === System Modification ===
    /// Number of dd disk dump command usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dd_usage: u32,
    /// Number of mkfifo and mknod special file calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub special_file_creation: u32,
    /// iptables/firewall manipulation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub firewall_manipulation: u32,
}

/// PowerShell metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PowerShellMetrics {
    // === Execution ===
    /// Invoke-Expression (IEX) count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_expression_count: u32,
    /// Number of Invoke-Command remote call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_command_count: u32,
    /// Number of Start-Process subprocess launches
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub start_process_count: u32,
    /// Number of -EncodedCommand parameter usages
    #[serde(default, skip_serializing_if = "is_false")]
    pub encoded_command_usage: bool,
    /// Number of & call operator invocations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_operator_count: u32,

    // === Download Cradles ===
    /// Number of Net.WebClient HTTP client usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webclient_count: u32,
    /// Number of Invoke-WebRequest HTTP call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webrequest_count: u32,
    /// Number of DownloadString method call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadstring_count: u32,
    /// Number of DownloadFile method call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadfile_count: u32,
    /// Number of BITS file transfer command uses
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bitstransfer_count: u32,

    // === Obfuscation Techniques ===
    /// Tick character obfuscation (`s`t`r)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tick_obfuscation: u32,
    /// Caret obfuscation (^s^t^r)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub caret_obfuscation: u32,
    /// String concatenation ("str" + "ing")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub concat_obfuscation: u32,
    /// Format string obfuscation ("{0}{1}" -f)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub format_obfuscation: u32,
    /// Number of -replace operator obfuscation patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_obfuscation: u32,
    /// Number of [char[]] character array usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_array_count: u32,
    /// Variable substitution tricks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub variable_substitution: u32,

    // === Reflection/Bypass ===
    /// [Reflection.Assembly] usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_assembly: u32,
    /// Add-Type count (compile C#)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub add_type_count: u32,
    /// Type accelerators [type]::method
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_accelerators: u32,
    /// Number of AMSI bypass technique indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub amsi_bypass_indicators: u32,
    /// Number of ETW tracing bypass indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub etw_bypass_indicators: u32,
    /// Number of execution policy bypass patterns
    #[serde(default, skip_serializing_if = "is_false")]
    pub execution_policy_bypass: bool,

    // === Suspicious Cmdlets ===
    /// Number of Get-Process cmdlet invocations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_process_count: u32,
    /// Get-WmiObject/Get-CimInstance
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wmi_cim_count: u32,
    /// Number of New-Object instantiation calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub new_object_count: u32,
    /// Number of registry read and write access calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub registry_access: u32,
    /// Credential access patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub credential_access: u32,

    // === Encoding ===
    /// Number of base64 encoded string patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_patterns: u32,
    /// Number of gzip decompression call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_decompress: u32,
    /// Number of SecureString credential handling calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub securestring_usage: u32,
}

/// PHP metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PhpMetrics {
    // === Dangerous Functions ===
    /// Number of eval() dynamic code execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// Number of assert() calls with string argument
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_string_count: u32,
    /// create_function() usage (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub create_function_count: u32,
    /// preg_replace with /e modifier
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub preg_replace_e_count: u32,
    /// Number of call_user_func dynamic calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_user_func_count: u32,

    // === Command Execution ===
    /// Number of system() command execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// Number of exec() subprocess execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Number of shell_exec() command calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_exec_count: u32,
    /// Number of passthru() command output calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub passthru_count: u32,
    /// Number of backtick subprocess execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// Number of proc_open() subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_open_count: u32,
    /// Number of popen() subprocess pipe calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub popen_count: u32,

    // === File Operations ===
    /// Number of dynamic include and require calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_require_dynamic: u32,
    /// Number of file_get_contents call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_get_contents_count: u32,
    /// Number of file_put_contents call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_put_contents_count: u32,
    /// Number of fwrite file write call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fwrite_count: u32,

    // === Obfuscation ===
    /// Variable variables ($$var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub variable_variables: u32,
    /// Number of extract() variable import calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extract_count: u32,
    /// Number of chr and pack encoding call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_pack_count: u32,
    /// Number of base64_decode call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// Number of gzinflate decompression call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzinflate_count: u32,
    /// Number of gzuncompress decompression calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzuncompress_count: u32,
    /// Number of str_rot13 encoding call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub str_rot13_count: u32,
    /// Number of hex2bin decode call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex2bin_count: u32,

    // === Network ===
    /// Number of curl HTTP client call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_count: u32,
    /// Number of fsockopen socket open calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fsockopen_count: u32,
    /// Number of stream_socket call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_socket_count: u32,

    // === Suspicious Patterns ===
    /// Number of @ error suppression operators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub error_suppression: u32,
    /// Number of ini_set configuration change calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ini_set_count: u32,
    /// Number of $GLOBALS superglobal access sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub globals_access: u32,
    /// $_REQUEST/$_GET/$_POST access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub superglobal_input: u32,
}

/// Ruby metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct RubyMetrics {
    // === Dynamic Execution ===
    /// Number of eval dynamic code execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// Number of instance_eval context switch calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instance_eval_count: u32,
    /// class_eval/module_eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_module_eval_count: u32,
    /// Number of send and public_send dispatch calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub send_count: u32,
    /// method_missing definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_missing_count: u32,
    /// Number of define_method dynamic definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub define_method_count: u32,

    // === Command Execution ===
    /// Number of system() subprocess execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// Number of exec() process replacement calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Number of backtick subprocess execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// Number of Open3 and spawn subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spawn_popen_count: u32,

    // === Serialization ===
    /// Number of Marshal.load deserialization calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_load_count: u32,
    /// Number of YAML.load unsafe deserialization calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_count: u32,

    // === Metaprogramming ===
    /// const_get/const_set usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub const_manipulation: u32,
    /// Number of binding object capture calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub binding_usage: u32,
    /// Number of ObjectSpace introspection call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectspace_usage: u32,

    // === Obfuscation ===
    /// Number of pack and unpack binary call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// Number of chr and ord conversion call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_ord_count: u32,
}

/// Perl metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PerlMetrics {
    // === Dynamic Execution ===
    /// Number of eval STRING dynamic execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_string_count: u32,
    /// Number of eval BLOCK exception-catch usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_block_count: u32,
    /// Number of do FILE execution call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub do_count: u32,
    /// Number of dynamic require call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub require_dynamic: u32,

    // === Command Execution ===
    /// Number of system() subprocess execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// Number of exec() process replacement calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Number of backtick and qx subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_qx_count: u32,
    /// Number of open() calls with pipe operator
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub open_pipe_count: u32,

    // === Obfuscation ===
    /// Number of pack and unpack binary calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// Number of chr and ord character conversion calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_ord_count: u32,
    /// Symbolic dereferencing ($$var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symbolic_deref_count: u32,
    /// Regex code execution (?{})
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub regex_code_count: u32,

    // === Special Blocks ===
    /// BEGIN/END/CHECK/INIT blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub special_block_count: u32,
    /// Number of tie variable-overloading call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tie_usage: u32,
    /// Number of AUTOLOAD method definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub autoload_count: u32,
}

/// Go-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct GoMetrics {
    // === Dangerous Packages ===
    /// Number of unsafe package usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_usage: u32,
    /// Number of reflect package call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflect_usage: u32,
    /// Number of CGo foreign-function interface usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_usage: u32,
    /// Number of plugin package load calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub plugin_usage: u32,
    /// Number of direct syscall package invocations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub syscall_direct: u32,

    // === Execution ===
    /// Number of exec.Command subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_command_count: u32,
    /// Number of os.StartProcess invocations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_startprocess_count: u32,

    // === Network ===
    /// Number of net.Dial network connection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub net_dial_count: u32,
    /// Number of net/http client and server usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub http_usage: u32,
    /// Number of raw socket creation call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_socket_count: u32,

    // === Embedding ===
    /// Number of //go:embed file-embedding directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embed_directive_count: u32,
    /// Embedded binary data size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_binary_size: u64,

    // === Build Configuration ===
    /// Number of //go:linkname symbol-aliasing directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linkname_count: u32,
    /// Number of //go:noescape compiler directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noescape_count: u32,
    /// Number of #cgo compiler/linker directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_directives: u32,

    // === Patterns ===
    /// Number of package-level init() functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub init_function_count: u32,
    /// Blank imports (import _ "pkg")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub blank_import_count: u32,
}

/// Rust-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct RustMetrics {
    // === Unsafe ===
    /// Number of unsafe code blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// Number of unsafe fn function declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_fn_count: u32,
    /// Number of raw pointer dereference operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_pointer_count: u32,
    /// std::mem::transmute usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub transmute_count: u32,

    // === FFI ===
    /// Number of extern fn FFI function declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_fn_count: u32,
    /// Number of extern block FFI declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_block_count: u32,
    /// Number of #[link] library link attributes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub link_attribute_count: u32,

    // === Execution ===
    /// std::process::Command usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub command_count: u32,
    /// Number of shell command execution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_count: u32,

    // === Embedding ===
    /// include_bytes! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_bytes_count: u32,
    /// Number of include_str! file-embed calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_str_count: u32,
    /// Total bytes of include_bytes! embedded data
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_size: u64,

    // === Macros ===
    /// Number of procedural macro call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_macro_count: u32,
    /// Number of macro_rules! macro definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_rules_count: u32,
    /// Number of asm! inline assembly macro usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub asm_macro_count: u32,
}

/// C/C++ metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct CMetrics {
    // === Dangerous Constructs ===
    /// Number of inline assembly blocks in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub inline_asm_count: u32,
    /// Number of goto statements in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub goto_count: u32,
    /// Number of setjmp and longjmp call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setjmp_longjmp_count: u32,
    /// Computed goto (goto *ptr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_goto_count: u32,

    // === Function Pointers ===
    /// Function pointer declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_count: u32,
    /// Number of function pointer array declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_array_count: u32,

    // === Memory Operations ===
    /// malloc/free calls (for ratio)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub malloc_count: u32,
    /// Number of free() memory deallocation calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub free_count: u32,
    /// Number of void pointer declarations and casts
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub void_pointer_count: u32,
    /// Number of explicit type cast operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cast_count: u32,
    /// Number of memcpy and memmove call sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memcpy_count: u32,

    // === Preprocessor ===
    /// Number of macro definitions in the source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_count: u32,
    /// Conditional compilation (#ifdef)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub conditional_compile_count: u32,
    /// Number of #pragma compiler directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pragma_count: u32,

    // === Suspicious Patterns ===
    /// Shellcode-like byte arrays
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shellcode_arrays: u32,
    /// Number of loops containing XOR operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xor_loops: u32,
    /// VirtualAlloc/mmap with EXEC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_memory_alloc: u32,
}

/// Java source metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JavaSourceMetrics {
    // === Reflection ===
    /// Number of Class.forName reflection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_forname_count: u32,
    /// getMethod/getDeclaredMethod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_method_count: u32,
    /// Number of Method.invoke reflection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_count: u32,
    /// setAccessible(true) calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub set_accessible_count: u32,

    // === Execution ===
    /// Number of Runtime.exec subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runtime_exec_count: u32,
    /// Number of ProcessBuilder subprocess calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub processbuilder_count: u32,

    // === ClassLoading ===
    /// Number of URLClassLoader dynamic load calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub urlclassloader_count: u32,
    /// Number of defineClass bytecode injection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub defineclass_count: u32,
    /// Number of custom ClassLoader definitions
    #[serde(default, skip_serializing_if = "is_false")]
    pub custom_classloader: bool,

    // === Serialization ===
    /// Number of ObjectInputStream deserialization sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectinputstream_count: u32,
    /// Number of readObject deserialization overrides
    #[serde(default, skip_serializing_if = "is_false")]
    pub readobject_override: bool,

    // === Scripting ===
    /// Number of ScriptEngine dynamic evaluation calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scriptengine_count: u32,

    // === JNI ===
    /// native method declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_method_count: u32,
    /// Number of System.loadLibrary native calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_library_count: u32,
}

/// Lua metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct LuaMetrics {
    /// Number of loadstring and load eval calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadstring_count: u32,
    /// Number of dofile file execution calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dofile_count: u32,
    /// Number of loadfile file loading calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadfile_count: u32,
    /// Number of os.execute shell command calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_execute_count: u32,
    /// Number of io.popen subprocess pipe calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub io_popen_count: u32,
    /// Number of debug library function calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_library_usage: u32,
    /// Number of setfenv and getfenv env calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setfenv_count: u32,
    /// Number of rawset and rawget bypass calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rawset_rawget_count: u32,
    /// string.dump (bytecode generation)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_dump_count: u32,
}

/// C# metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct CSharpMetrics {
    // === P/Invoke ===
    /// Number of DllImport P/Invoke declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dllimport_count: u32,
    /// Number of Marshal class method calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,

    // === Reflection ===
    /// Number of Assembly.Load and related calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assembly_load_count: u32,
    /// Activator.CreateInstance usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub activator_count: u32,
    /// Number of Type.GetMethod reflection calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_invoke: u32,

    // === Execution ===
    /// Number of Process.Start invocations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_start_count: u32,

    // === Network ===
    /// WebClient/HttpClient usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub web_client_count: u32,
    /// Number of socket creation or usage sites
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub socket_count: u32,

    // === Unsafe ===
    /// Number of unsafe code blocks in source
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// Number of fixed statements in unsafe contexts
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixed_statement_count: u32,

    // === Suspicious ===
    /// Number of CryptoStream and cipher usages
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto_usage: u32,
    /// Number of Windows Registry access calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub registry_access: u32,
}

// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== PythonMetrics Tests ====================

    #[test]
    fn test_python_metrics_default() {
        let metrics = PythonMetrics::default();
        assert_eq!(metrics.eval_count, 0);
        assert_eq!(metrics.exec_count, 0);
        assert!(!metrics.getattribute_override);
    }

    #[test]
    fn test_python_metrics_dynamic_execution() {
        let metrics = PythonMetrics {
            eval_count: 5,
            exec_count: 3,
            compile_count: 1,
            dunder_import_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.eval_count, 5);
        assert_eq!(metrics.exec_count, 3);
    }

    #[test]
    fn test_python_metrics_obfuscation() {
        let metrics = PythonMetrics {
            chr_calls: 50,
            ord_calls: 45,
            lambda_count: 20,
            nested_lambda_count: 5,
            ..Default::default()
        };
        assert_eq!(metrics.chr_calls, 50);
        assert_eq!(metrics.nested_lambda_count, 5);
    }

    #[test]
    fn test_python_metrics_serialization() {
        let metrics = PythonMetrics {
            pickle_usage: 2,
            marshal_usage: 1,
            yaml_load_unsafe: 1,
            ..Default::default()
        };
        assert_eq!(metrics.pickle_usage, 2);
        assert_eq!(metrics.yaml_load_unsafe, 1);
    }

    #[test]
    fn test_python_metrics_magic_methods() {
        let metrics = PythonMetrics {
            dunder_method_count: 15,
            getattribute_override: true,
            new_override: true,
            descriptor_protocol: true,
            ..Default::default()
        };
        assert!(metrics.getattribute_override);
        assert!(metrics.descriptor_protocol);
    }

    // ==================== JavaScriptMetrics Tests ====================

    #[test]
    fn test_javascript_metrics_default() {
        let metrics = JavaScriptMetrics::default();
        assert_eq!(metrics.eval_count, 0);
        assert_eq!(metrics.function_constructor, 0);
    }

    #[test]
    fn test_javascript_metrics_dynamic_execution() {
        let metrics = JavaScriptMetrics {
            eval_count: 10,
            function_constructor: 5,
            settimeout_string: 3,
            document_write: 2,
            ..Default::default()
        };
        assert_eq!(metrics.eval_count, 10);
        assert_eq!(metrics.function_constructor, 5);
    }

    #[test]
    fn test_javascript_metrics_obfuscation() {
        let metrics = JavaScriptMetrics {
            from_char_code_count: 30,
            char_code_at_count: 25,
            array_join_strings: 10,
            split_reverse_join: 5,
            ..Default::default()
        };
        assert_eq!(metrics.from_char_code_count, 30);
        assert_eq!(metrics.split_reverse_join, 5);
    }

    // ==================== PowerShellMetrics Tests ====================

    #[test]
    fn test_powershell_metrics_default() {
        let metrics = PowerShellMetrics::default();
        assert_eq!(metrics.invoke_expression_count, 0);
        assert_eq!(metrics.amsi_bypass_indicators, 0);
    }

    #[test]
    fn test_powershell_metrics_execution() {
        let metrics = PowerShellMetrics {
            invoke_expression_count: 5,
            invoke_command_count: 3,
            webrequest_count: 10,
            ..Default::default()
        };
        assert_eq!(metrics.invoke_expression_count, 5);
        assert_eq!(metrics.webrequest_count, 10);
    }

    #[test]
    fn test_powershell_metrics_bypass() {
        let metrics = PowerShellMetrics {
            amsi_bypass_indicators: 3,
            etw_bypass_indicators: 2,
            execution_policy_bypass: true,
            ..Default::default()
        };
        assert_eq!(metrics.amsi_bypass_indicators, 3);
        assert!(metrics.execution_policy_bypass);
    }

    // ==================== ShellMetrics Tests ====================

    #[test]
    fn test_shell_metrics_default() {
        let metrics = ShellMetrics::default();
        assert_eq!(metrics.eval_count, 0);
        assert_eq!(metrics.curl_wget_count, 0);
    }

    #[test]
    fn test_shell_metrics_creation() {
        let metrics = ShellMetrics {
            eval_count: 50,
            exec_count: 10,
            curl_wget_count: 5,
            nc_netcat_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.eval_count, 50);
        assert_eq!(metrics.curl_wget_count, 5);
    }

    // ==================== PhpMetrics Tests ====================

    #[test]
    fn test_php_metrics_default() {
        let metrics = PhpMetrics::default();
        assert_eq!(metrics.eval_count, 0);
        assert_eq!(metrics.preg_replace_e_count, 0);
    }

    #[test]
    fn test_php_metrics_execution() {
        let metrics = PhpMetrics {
            eval_count: 5,
            shell_exec_count: 3,
            passthru_count: 2,
            preg_replace_e_count: 1,
            ..Default::default()
        };
        assert_eq!(metrics.eval_count, 5);
        assert_eq!(metrics.preg_replace_e_count, 1);
    }

    // ==================== RubyMetrics Tests ====================

    #[test]
    fn test_ruby_metrics_default() {
        let metrics = RubyMetrics::default();
        assert_eq!(metrics.eval_count, 0);
    }

    #[test]
    fn test_ruby_metrics_creation() {
        let metrics = RubyMetrics {
            eval_count: 3,
            instance_eval_count: 2,
            binding_usage: 1,
            ..Default::default()
        };
        assert_eq!(metrics.eval_count, 3);
        assert_eq!(metrics.instance_eval_count, 2);
    }

    // ==================== GoMetrics Tests ====================

    #[test]
    fn test_go_metrics_default() {
        let metrics = GoMetrics::default();
        assert_eq!(metrics.unsafe_usage, 0);
        assert_eq!(metrics.cgo_usage, 0);
    }

    #[test]
    fn test_go_metrics_creation() {
        let metrics = GoMetrics {
            unsafe_usage: 10,
            reflect_usage: 5,
            cgo_usage: 3,
            plugin_usage: 2,
            ..Default::default()
        };
        assert_eq!(metrics.unsafe_usage, 10);
        assert_eq!(metrics.cgo_usage, 3);
    }

    // ==================== RustMetrics Tests ====================

    #[test]
    fn test_rust_metrics_default() {
        let metrics = RustMetrics::default();
        assert_eq!(metrics.unsafe_block_count, 0);
        assert_eq!(metrics.raw_pointer_count, 0);
    }

    #[test]
    fn test_rust_metrics_creation() {
        let metrics = RustMetrics {
            unsafe_block_count: 15,
            unsafe_fn_count: 5,
            raw_pointer_count: 10,
            transmute_count: 3,
            ..Default::default()
        };
        assert_eq!(metrics.unsafe_block_count, 15);
        assert_eq!(metrics.raw_pointer_count, 10);
    }

    // ==================== CMetrics Tests ====================

    #[test]
    fn test_c_metrics_default() {
        let metrics = CMetrics::default();
        assert_eq!(metrics.malloc_count, 0);
        assert_eq!(metrics.inline_asm_count, 0);
    }

    #[test]
    fn test_c_metrics_creation() {
        let metrics = CMetrics {
            malloc_count: 50,
            free_count: 45,
            inline_asm_count: 10,
            goto_count: 5,
            ..Default::default()
        };
        assert_eq!(metrics.malloc_count, 50);
        assert_eq!(metrics.inline_asm_count, 10);
    }

    // ==================== PerlMetrics Tests ====================

    #[test]
    fn test_perl_metrics_default() {
        let metrics = PerlMetrics::default();
        assert_eq!(metrics.eval_string_count, 0);
    }

    #[test]
    fn test_perl_metrics_creation() {
        let metrics = PerlMetrics {
            eval_string_count: 5,
            eval_block_count: 3,
            backtick_qx_count: 10,
            system_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.eval_string_count, 5);
        assert_eq!(metrics.backtick_qx_count, 10);
    }

    // ==================== LuaMetrics Tests ====================

    #[test]
    fn test_lua_metrics_default() {
        let metrics = LuaMetrics::default();
        assert_eq!(metrics.loadstring_count, 0);
    }

    #[test]
    fn test_lua_metrics_creation() {
        let metrics = LuaMetrics {
            loadstring_count: 5,
            dofile_count: 3,
            os_execute_count: 10,
            ..Default::default()
        };
        assert_eq!(metrics.loadstring_count, 5);
        assert_eq!(metrics.os_execute_count, 10);
    }

    // ==================== JavaSourceMetrics Tests ====================

    #[test]
    fn test_java_source_metrics_default() {
        let metrics = JavaSourceMetrics::default();
        assert_eq!(metrics.invoke_count, 0);
        assert_eq!(metrics.native_method_count, 0);
    }

    #[test]
    fn test_java_source_metrics_creation() {
        let metrics = JavaSourceMetrics {
            invoke_count: 20,
            class_forname_count: 10,
            native_method_count: 5,
            ..Default::default()
        };
        assert_eq!(metrics.invoke_count, 20);
        assert_eq!(metrics.native_method_count, 5);
    }

    // ==================== CSharpMetrics Tests ====================

    #[test]
    fn test_csharp_metrics_default() {
        let metrics = CSharpMetrics::default();
        assert_eq!(metrics.reflection_invoke, 0);
        assert_eq!(metrics.unsafe_block_count, 0);
    }

    #[test]
    fn test_csharp_metrics_creation() {
        let metrics = CSharpMetrics {
            reflection_invoke: 15,
            dllimport_count: 10,
            unsafe_block_count: 5,
            registry_access: 3,
            ..Default::default()
        };
        assert_eq!(metrics.reflection_invoke, 15);
        assert_eq!(metrics.dllimport_count, 10);
    }
}

// =============================================================================
// VALID FIELD PATHS FOR YAML VALIDATION
// =============================================================================

// Stub implementations - return empty for now, can be filled with actual fields if needed
