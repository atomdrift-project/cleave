//! Import/dependency metrics analyzer
//!
//! Analyzes import statements extracted from source code to detect patterns
//! like dynamic imports, wildcard imports, and unusual dependency ratios.

use crate::types::{Import, ImportMetrics};
use rustc_hash::FxHashSet;

/// Analyze imports to compute import metrics
/// Takes the imports already extracted from the file
#[must_use]
pub(crate) fn analyze_imports(imports: &[Import], file_type: &str) -> ImportMetrics {
    if imports.is_empty() {
        return ImportMetrics::default();
    }

    let mut metrics = ImportMetrics {
        total: imports.len() as u32,
        ..Default::default()
    };

    let mut unique_modules: FxHashSet<String> = FxHashSet::default();
    let mut stdlib_count = 0;
    let mut third_party_count = 0;
    let mut relative_count = 0;
    let mut dynamic_count = 0;
    let mut wildcard_count = 0;
    let mut aliased_count = 0;

    for import in imports {
        let module = &import.symbol;
        unique_modules.insert(module.clone());

        // Check if relative import
        if module.starts_with('.') || module.starts_with("./") || module.starts_with("../") {
            relative_count += 1;
        }

        // Check if stdlib vs third-party
        if is_stdlib_module(module, file_type) {
            stdlib_count += 1;
        } else {
            third_party_count += 1;
        }

        // Check for dynamic imports (already detected by symbol_extraction)
        if import.symbol.contains("__import__")
            || import.symbol.contains("importlib")
            || import.symbol.contains("require")
        {
            dynamic_count += 1;
        }

        // Check for wildcard imports (indicated by *)
        if module.contains('*') || module.ends_with(".*") {
            wildcard_count += 1;
        }

        // Check for aliased imports (indicated by "as" in the symbol or library field)
        if import.library.is_some() || module.contains(" as ") {
            aliased_count += 1;
        }
    }

    metrics.unique_modules = unique_modules.len() as u32;
    metrics.stdlib_count = stdlib_count;
    metrics.third_party_count = third_party_count;
    metrics.relative_imports = relative_count;
    metrics.dynamic_imports = dynamic_count;
    metrics.wildcard_imports = wildcard_count;
    metrics.aliased_imports = aliased_count;

    // Calculate ratios
    let total = metrics.total as f32;
    if total > 0.0 {
        metrics.stdlib_ratio = stdlib_count as f32 / total;
        metrics.third_party_ratio = third_party_count as f32 / total;
        metrics.relative_ratio = relative_count as f32 / total;
    }

    metrics
}

/// Check if a module is part of the standard library
fn is_stdlib_module(module: &str, file_type: &str) -> bool {
    match file_type {
        "python" => is_python_stdlib(module),
        "javascript" | "typescript" => is_node_stdlib(module),
        "go" => is_go_stdlib(module),
        "ruby" => is_ruby_stdlib(module),
        "perl" => is_perl_stdlib(module),
        "lua" => is_lua_stdlib(module),
        _ => false,
    }
}

/// Python standard library modules (common ones)
fn is_python_stdlib(module: &str) -> bool {
    // Extract just the top-level module name
    let top_level = module.split('.').next().unwrap_or(module);

    matches!(
        top_level,
        "abc"
            | "argparse"
            | "array"
            | "ast"
            | "asyncio"
            | "base64"
            | "binascii"
            | "builtins"
            | "bz2"
            | "calendar"
            | "collections"
            | "concurrent"
            | "configparser"
            | "copy"
            | "csv"
            | "ctypes"
            | "dataclasses"
            | "datetime"
            | "decimal"
            | "difflib"
            | "dis"
            | "email"
            | "enum"
            | "errno"
            | "faulthandler"
            | "fcntl"
            | "filecmp"
            | "fnmatch"
            | "functools"
            | "gc"
            | "getpass"
            | "glob"
            | "gzip"
            | "hashlib"
            | "hmac"
            | "http"
            | "importlib"
            | "inspect"
            | "io"
            | "ipaddress"
            | "itertools"
            | "json"
            | "logging"
            | "math"
            | "mimetypes"
            | "multiprocessing"
            | "operator"
            | "os"
            | "pathlib"
            | "pickle"
            | "platform"
            | "pprint"
            | "pwd"
            | "queue"
            | "random"
            | "re"
            | "resource"
            | "select"
            | "shlex"
            | "shutil"
            | "signal"
            | "socket"
            | "sqlite3"
            | "ssl"
            | "stat"
            | "string"
            | "struct"
            | "subprocess"
            | "sys"
            | "syslog"
            | "tarfile"
            | "tempfile"
            | "textwrap"
            | "threading"
            | "time"
            | "timeit"
            | "traceback"
            | "types"
            | "typing"
            | "unittest"
            | "urllib"
            | "uuid"
            | "warnings"
            | "weakref"
            | "xml"
            | "zipfile"
            | "zlib"
    )
}

/// Node.js built-in modules
fn is_node_stdlib(module: &str) -> bool {
    // Node modules may have node: prefix
    let module = module.strip_prefix("node:").unwrap_or(module);

    matches!(
        module,
        "assert"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "sys"
            | "timers"
            | "tls"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
}

/// Go standard library packages (common ones)
fn is_go_stdlib(module: &str) -> bool {
    // Go stdlib packages start with standard names
    let top_level = module.split('/').next().unwrap_or(module);

    matches!(
        top_level,
        "archive"
            | "bufio"
            | "bytes"
            | "compress"
            | "container"
            | "context"
            | "crypto"
            | "database"
            | "debug"
            | "encoding"
            | "errors"
            | "expvar"
            | "flag"
            | "fmt"
            | "go"
            | "hash"
            | "html"
            | "image"
            | "index"
            | "io"
            | "log"
            | "math"
            | "mime"
            | "net"
            | "os"
            | "path"
            | "plugin"
            | "reflect"
            | "regexp"
            | "runtime"
            | "sort"
            | "strconv"
            | "strings"
            | "sync"
            | "syscall"
            | "testing"
            | "text"
            | "time"
            | "unicode"
            | "unsafe"
    )
}

/// Ruby standard library
fn is_ruby_stdlib(module: &str) -> bool {
    matches!(
        module,
        "abbrev"
            | "base64"
            | "benchmark"
            | "cgi"
            | "csv"
            | "date"
            | "dbm"
            | "delegate"
            | "digest"
            | "drb"
            | "erb"
            | "etc"
            | "fcntl"
            | "fiddle"
            | "fileutils"
            | "find"
            | "forwardable"
            | "getoptlong"
            | "io/console"
            | "io/wait"
            | "ipaddr"
            | "json"
            | "logger"
            | "matrix"
            | "monitor"
            | "net/http"
            | "net/https"
            | "nkf"
            | "open-uri"
            | "openssl"
            | "optparse"
            | "pathname"
            | "pp"
            | "prettyprint"
            | "prime"
            | "pstore"
            | "psych"
            | "pty"
            | "readline"
            | "resolv"
            | "rexml"
            | "rinda"
            | "ripper"
            | "rss"
            | "securerandom"
            | "set"
            | "shellwords"
            | "singleton"
            | "socket"
            | "stringio"
            | "strscan"
            | "tempfile"
            | "thread"
            | "time"
            | "timeout"
            | "tmpdir"
            | "tsort"
            | "un"
            | "uri"
            | "weakref"
            | "webrick"
            | "yaml"
            | "zlib"
    )
}

/// Perl core modules
fn is_perl_stdlib(module: &str) -> bool {
    matches!(
        module,
        "strict"
            | "warnings"
            | "Carp"
            | "Data::Dumper"
            | "Exporter"
            | "File::Basename"
            | "File::Copy"
            | "File::Find"
            | "File::Path"
            | "File::Spec"
            | "File::Temp"
            | "FindBin"
            | "Getopt::Long"
            | "IO::File"
            | "IO::Handle"
            | "IO::Socket"
            | "List::Util"
            | "POSIX"
            | "Scalar::Util"
            | "Socket"
            | "Storable"
            | "Symbol"
            | "Term::ANSIColor"
            | "Test::More"
            | "Time::HiRes"
            | "Time::Local"
            | "constant"
            | "lib"
            | "parent"
            | "utf8"
    )
}

/// Lua standard library
fn is_lua_stdlib(module: &str) -> bool {
    matches!(
        module,
        "coroutine" | "debug" | "io" | "math" | "os" | "package" | "string" | "table" | "utf8"
    )
}
