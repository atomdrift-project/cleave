//! Language-specific metrics for source code analysis

use flayer_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_u32, is_zero_u64};

// =============================================================================
// LANGUAGE-SPECIFIC METRICS
// =============================================================================

/// Python-specific metrics for obfuscation/malware detection
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PythonMetrics {
    // === Dynamic Execution ===
    /// eval() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// compile() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compile_count: u32,
    /// __import__() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_import_count: u32,
    /// importlib usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub importlib_count: u32,
    /// getattr/setattr/delattr calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub attr_manipulation_count: u32,

    // === Obfuscation Patterns ===
    /// chr() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_calls: u32,
    /// ord() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ord_calls: u32,
    /// Lambda expressions
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
    /// __builtins__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub builtins_access: u32,
    /// type() calls (metaclass tricks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_calls: u32,
    /// __class__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_access: u32,
    /// vars() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_calls: u32,
    /// dir() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dir_calls: u32,

    // === Serialization (RCE vectors) ===
    /// pickle usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pickle_usage: u32,
    /// marshal usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,
    /// yaml.load (unsafe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_unsafe: u32,
    /// shelve usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shelve_usage: u32,

    // === Decorators ===
    /// Total decorators
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
    /// __new__ override
    #[serde(default, skip_serializing_if = "is_false")]
    pub new_override: bool,
    /// Descriptor protocol (__get__, __set__)
    #[serde(default, skip_serializing_if = "is_false")]
    pub descriptor_protocol: bool,

    // === Encoding/Decoding ===
    /// base64 module calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_calls: u32,
    /// codecs module calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub codecs_calls: u32,
    /// zlib/gzip calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compression_calls: u32,
    /// rot13 usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub rot13_usage: bool,

    // === Control Flow ===
    /// try/except blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub try_except_count: u32,
    /// Bare except (except:)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bare_except_count: u32,
    /// except Exception (too broad)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub broad_except_count: u32,
    /// Maximum nesting depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,

    // === Additional Structural Metrics ===
    /// vars() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_access: u32,
    /// type() manipulation (3-arg form)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_manipulation: u32,
    /// __code__ object access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_object_access: u32,
    /// Frame access (sys._getframe, inspect.currentframe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub frame_access: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Metaclass usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub metaclass_usage: u32,
    /// with statement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement_count: u32,
    /// assert statement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_count: u32,
}

/// JavaScript/TypeScript metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JavaScriptMetrics {
    // === Dynamic Execution ===
    /// eval() calls
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
    /// document.write calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub document_write: u32,

    // === Obfuscation Patterns ===
    /// String.fromCharCode calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub from_char_code_count: u32,
    /// charCodeAt calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_code_at_count: u32,
    /// Array.join for string building
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_strings: u32,
    /// split().reverse().join() patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub split_reverse_join: u32,
    /// Chained .replace() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_chain_count: u32,
    /// Computed property access obj[var]
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_property_access: u32,

    // === Encoding ===
    /// atob/btoa calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub atob_btoa_count: u32,
    /// escape/unescape calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub escape_unescape: u32,
    /// decodeURIComponent calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decode_uri_component: u32,

    // === Suspicious Constructs ===
    /// with statements (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement: u32,
    /// debugger statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debugger_statements: u32,
    /// arguments.caller/callee access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub caller_callee_access: u32,
    /// Prototype pollution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub prototype_pollution_patterns: u32,
    /// __proto__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proto_access: u32,

    // === Functions & Closures ===
    /// IIFE count (function(){})()
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub iife_count: u32,
    /// Maximum nested IIFE depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_iife_depth: u32,
    /// Arrow function count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arrow_function_count: u32,
    /// Maximum closure depth
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
    /// innerHTML assignments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub innerhtml_writes: u32,
    /// Script element creation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_element_creation: u32,
    /// Event handler strings (onclick="...")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub event_handler_strings: u32,
    /// XHR/fetch usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub network_requests: u32,
}

/// Shell script metrics (bash/sh/zsh)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ShellMetrics {
    // === Command Execution ===
    /// eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// source or . command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub source_count: u32,
    /// exec command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// bash -c usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bash_c_count: u32,
    /// xargs usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xargs_count: u32,

    // === Network Operations ===
    /// curl/wget usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_wget_count: u32,
    /// nc/netcat usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nc_netcat_count: u32,
    /// /dev/tcp or /dev/udp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_tcp_count: u32,
    /// DNS exfiltration patterns (dig, nslookup abuse)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dns_exfil_patterns: u32,
    /// ssh/scp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ssh_scp_count: u32,

    // === Encoding/Decoding ===
    /// base64 decode usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// xxd usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxd_count: u32,
    /// printf with hex escapes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub printf_hex_count: u32,
    /// openssl encryption usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub openssl_enc_count: u32,
    /// gzip/gunzip usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_count: u32,

    // === Pipes & Redirection ===
    /// Pipe count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_count: u32,
    /// Maximum pipe chain depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_depth_max: u32,
    /// Here-doc count
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
    /// Background job usage (&)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub background_jobs: u32,
    /// nohup/disown usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nohup_disown_count: u32,
    /// cron/at manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub cron_at_manipulation: bool,
    /// chmod +x usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chmod_x_count: u32,
    /// shred/rm -rf usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub secure_delete_count: u32,

    // === Variable Tricks ===
    /// Indirect variable expansion ${!var}
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_vars: u32,
    /// eval with variable expansion
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_expansion: u32,
    /// IFS manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub ifs_manipulation: bool,
    /// PATH manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_manipulation: bool,

    // === Timing/Evasion ===
    /// sleep commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sleep_count: u32,
    /// timeout command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timeout_count: u32,
    /// trap commands (signal handling)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trap_count: u32,

    // === System Modification ===
    /// dd usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dd_usage: u32,
    /// mkfifo/mknod usage
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
    /// Invoke-Command count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_command_count: u32,
    /// Start-Process count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub start_process_count: u32,
    /// -EncodedCommand usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub encoded_command_usage: bool,
    /// & call operator abuse
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_operator_count: u32,

    // === Download Cradles ===
    /// Net.WebClient usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webclient_count: u32,
    /// Invoke-WebRequest
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webrequest_count: u32,
    /// DownloadString calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadstring_count: u32,
    /// DownloadFile calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadfile_count: u32,
    /// BitsTransfer usage
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
    /// -replace obfuscation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_obfuscation: u32,
    /// [char[]] array usage
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
    /// AMSI bypass indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub amsi_bypass_indicators: u32,
    /// ETW bypass indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub etw_bypass_indicators: u32,
    /// Execution policy bypass
    #[serde(default, skip_serializing_if = "is_false")]
    pub execution_policy_bypass: bool,

    // === Suspicious Cmdlets ===
    /// Get-Process usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_process_count: u32,
    /// Get-WmiObject/Get-CimInstance
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wmi_cim_count: u32,
    /// New-Object count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub new_object_count: u32,
    /// Registry access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub registry_access: u32,
    /// Credential access patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub credential_access: u32,

    // === Encoding ===
    /// Base64 patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_patterns: u32,
    /// Gzip decompression
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_decompress: u32,
    /// SecureString usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub securestring_usage: u32,
}

/// PHP metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PhpMetrics {
    // === Dangerous Functions ===
    /// eval() usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// assert() with string
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_string_count: u32,
    /// create_function() usage (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub create_function_count: u32,
    /// preg_replace with /e modifier
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub preg_replace_e_count: u32,
    /// call_user_func usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_user_func_count: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// shell_exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_exec_count: u32,
    /// passthru() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub passthru_count: u32,
    /// Backtick execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// proc_open() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_open_count: u32,
    /// popen() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub popen_count: u32,

    // === File Operations ===
    /// Dynamic include/require
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_require_dynamic: u32,
    /// file_get_contents usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_get_contents_count: u32,
    /// file_put_contents usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_put_contents_count: u32,
    /// fwrite usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fwrite_count: u32,

    // === Obfuscation ===
    /// Variable variables ($$var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub variable_variables: u32,
    /// extract() usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extract_count: u32,
    /// chr/pack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_pack_count: u32,
    /// base64_decode usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// gzinflate usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzinflate_count: u32,
    /// gzuncompress usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzuncompress_count: u32,
    /// str_rot13 usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub str_rot13_count: u32,
    /// hex2bin usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex2bin_count: u32,

    // === Network ===
    /// curl usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_count: u32,
    /// fsockopen usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fsockopen_count: u32,
    /// stream_socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_socket_count: u32,

    // === Suspicious Patterns ===
    /// @ error suppression
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub error_suppression: u32,
    /// ini_set calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ini_set_count: u32,
    /// $GLOBALS access
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
    /// eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// instance_eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instance_eval_count: u32,
    /// class_eval/module_eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_module_eval_count: u32,
    /// send/public_send usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub send_count: u32,
    /// method_missing definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_missing_count: u32,
    /// define_method usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub define_method_count: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Backtick/x{} execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// Open3/spawn usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spawn_popen_count: u32,

    // === Serialization ===
    /// Marshal.load usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_load_count: u32,
    /// YAML.load usage (unsafe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_count: u32,

    // === Metaprogramming ===
    /// const_get/const_set usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub const_manipulation: u32,
    /// binding usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub binding_usage: u32,
    /// ObjectSpace usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectspace_usage: u32,

    // === Obfuscation ===
    /// pack/unpack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// chr/ord usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_ord_count: u32,
}

/// Perl metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PerlMetrics {
    // === Dynamic Execution ===
    /// eval STRING usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_string_count: u32,
    /// eval BLOCK usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_block_count: u32,
    /// do FILE usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub do_count: u32,
    /// Dynamic require
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub require_dynamic: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Backtick/qx execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_qx_count: u32,
    /// open() with pipe
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub open_pipe_count: u32,

    // === Obfuscation ===
    /// pack/unpack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// chr/ord usage
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
    /// tie usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tie_usage: u32,
    /// AUTOLOAD definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub autoload_count: u32,
}

/// Go-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct GoMetrics {
    // === Dangerous Packages ===
    /// unsafe package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_usage: u32,
    /// reflect package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflect_usage: u32,
    /// CGo usage (import "C")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_usage: u32,
    /// plugin package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub plugin_usage: u32,
    /// syscall direct usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub syscall_direct: u32,

    // === Execution ===
    /// exec.Command usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_command_count: u32,
    /// os.StartProcess usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_startprocess_count: u32,

    // === Network ===
    /// net.Dial usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub net_dial_count: u32,
    /// http client/server usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub http_usage: u32,
    /// Raw socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_socket_count: u32,

    // === Embedding ===
    /// //go:embed directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embed_directive_count: u32,
    /// Embedded binary data size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_binary_size: u64,

    // === Build Configuration ===
    /// //go:linkname usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linkname_count: u32,
    /// //go:noescape usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noescape_count: u32,
    /// #cgo directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_directives: u32,

    // === Patterns ===
    /// init() function count
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
    /// unsafe blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// unsafe fn declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_fn_count: u32,
    /// Raw pointer operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_pointer_count: u32,
    /// std::mem::transmute usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub transmute_count: u32,

    // === FFI ===
    /// extern fn declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_fn_count: u32,
    /// extern blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_block_count: u32,
    /// #[link] attributes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub link_attribute_count: u32,

    // === Execution ===
    /// std::process::Command usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub command_count: u32,
    /// Shell execution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_count: u32,

    // === Embedding ===
    /// include_bytes! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_bytes_count: u32,
    /// include_str! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_str_count: u32,
    /// Embedded data size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_size: u64,

    // === Macros ===
    /// Procedural macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_macro_count: u32,
    /// macro_rules! definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_rules_count: u32,
    /// asm! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub asm_macro_count: u32,
}

/// C/C++ metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct CMetrics {
    // === Dangerous Constructs ===
    /// Inline assembly
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub inline_asm_count: u32,
    /// goto statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub goto_count: u32,
    /// setjmp/longjmp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setjmp_longjmp_count: u32,
    /// Computed goto (goto *ptr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_goto_count: u32,

    // === Function Pointers ===
    /// Function pointer declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_count: u32,
    /// Function pointer arrays
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_array_count: u32,

    // === Memory Operations ===
    /// malloc/free calls (for ratio)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub malloc_count: u32,
    /// free() calls (paired with malloc_count for leak/ratio analysis)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub free_count: u32,
    /// void pointer usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub void_pointer_count: u32,
    /// Type casts
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cast_count: u32,
    /// memcpy/memmove usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memcpy_count: u32,

    // === Preprocessor ===
    /// Macro definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_count: u32,
    /// Conditional compilation (#ifdef)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub conditional_compile_count: u32,
    /// #pragma directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pragma_count: u32,

    // === Suspicious Patterns ===
    /// Shellcode-like byte arrays
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shellcode_arrays: u32,
    /// XOR operation loops
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
    /// Class.forName usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_forname_count: u32,
    /// getMethod/getDeclaredMethod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_method_count: u32,
    /// invoke() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_count: u32,
    /// setAccessible(true) calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub set_accessible_count: u32,

    // === Execution ===
    /// Runtime.exec usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runtime_exec_count: u32,
    /// ProcessBuilder usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub processbuilder_count: u32,

    // === ClassLoading ===
    /// URLClassLoader usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub urlclassloader_count: u32,
    /// defineClass usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub defineclass_count: u32,
    /// Custom ClassLoader
    #[serde(default, skip_serializing_if = "is_false")]
    pub custom_classloader: bool,

    // === Serialization ===
    /// ObjectInputStream usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectinputstream_count: u32,
    /// readObject override
    #[serde(default, skip_serializing_if = "is_false")]
    pub readobject_override: bool,

    // === Scripting ===
    /// ScriptEngine usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scriptengine_count: u32,

    // === JNI ===
    /// native method declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_method_count: u32,
    /// System.loadLibrary calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_library_count: u32,
}

/// Lua metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct LuaMetrics {
    /// loadstring/load usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadstring_count: u32,
    /// dofile usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dofile_count: u32,
    /// loadfile usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadfile_count: u32,
    /// os.execute usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_execute_count: u32,
    /// io.popen usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub io_popen_count: u32,
    /// debug library usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_library_usage: u32,
    /// setfenv/getfenv usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setfenv_count: u32,
    /// rawset/rawget usage
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
    /// DllImport declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dllimport_count: u32,
    /// Marshal class usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,

    // === Reflection ===
    /// Assembly.Load* usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assembly_load_count: u32,
    /// Activator.CreateInstance usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub activator_count: u32,
    /// Type.GetMethod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_invoke: u32,

    // === Execution ===
    /// Process.Start usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_start_count: u32,

    // === Network ===
    /// WebClient/HttpClient usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub web_client_count: u32,
    /// Socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub socket_count: u32,

    // === Unsafe ===
    /// unsafe blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// fixed statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixed_statement_count: u32,

    // === Suspicious ===
    /// CryptoStream usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto_usage: u32,
    /// Registry access
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
