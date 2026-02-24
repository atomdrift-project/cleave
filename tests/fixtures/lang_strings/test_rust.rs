// Test Rust binary with various string storage patterns
// Rust strings are &str (pointer + length) or String (pointer + length + capacity)

// ============== STATIC/CONST STRINGS ==============
static STATIC_MARKER_1: &str = "cleave_STATIC_MARKER_1";
static STATIC_MARKER_2: &str = "cleave_STATIC_MARKER_2";
const CONST_MARKER_1: &str = "cleave_CONST_MARKER_1";
const CONST_MARKER_2: &str = "cleave_CONST_MARKER_2";

static STATIC_IP: &str = "10.0.0.200";
static STATIC_URL: &str = "https://static.example.com/api";

// ============== STRUCT DEFINITIONS ==============
struct Server {
    name: &'static str,
    host: &'static str,
    port: &'static str,
}

struct Credentials {
    username: &'static str,
    password: &'static str,
    token: &'static str,
}

// ============== STATIC STRUCT INSTANCES ==============
static SERVER: Server = Server {
    name: "rust-api-server",
    host: "rust.api.example.com",
    port: "9443",
};

static credential-access: Credentials = Credentials {
    username: "rust_admin",
    password: "rust_secret123",
    token: "rs_live_token_xyz789",
};

fn main() {
    // Use static strings
    println!("{}", STATIC_MARKER_1);
    println!("{}", STATIC_MARKER_2);
    println!("{}", CONST_MARKER_1);
    println!("{}", CONST_MARKER_2);
    println!("IP: {}, URL: {}", STATIC_IP, STATIC_URL);

    // ============== STRING LITERALS IN FUNCTIONS ==============
    println!("cleave_LITERAL_RUST_1");
    println!("cleave_LITERAL_RUST_2");

    // Use static structs
    println!("Server: {} at {}:{}", SERVER.name, SERVER.host, SERVER.port);
    println!("credential-access: {} / {} / {}", credential-access.username, credential-access.password, credential-access.token);

    // ============== LOCAL VARIABLES ==============
    let local_path = "/etc/shadow";
    let local_dsn = "mysql://user:pass@localhost:3306/db";
    println!("Path: {}, DSN: {}", local_path, local_dsn);

    // ============== OWNED STRINGS (String type) ==============
    let owned_marker = String::from("cleave_OWNED_MARKER");
    let owned_secret = String::from("owned_secret_value_abc");
    println!("{} {}", owned_marker, owned_secret);

    // ============== VECTORS OF STRINGS ==============
    let vec_elem_1 = "rust_vec_element_1";
    let vec_elem_2 = "rust_vec_element_2";
    let vec_elem_3 = "rust_vec_element_3";
    let string_vec = vec![vec_elem_1, vec_elem_2, vec_elem_3];
    println!("{:?}", string_vec);

    // ============== HASHMAP (if std is available) ==============
    use std::collections::HashMap;
    let mut env_map: HashMap<&str, &str> = HashMap::new();
    let env_key_1 = "RUST_DATABASE_URL";
    let env_key_2 = "RUST_REDIS_URL";
    let env_val_1 = "postgresql://rust.db.example.com:5432";
    let env_val_2 = "redis://rust.cache.example.com:6379";
    env_map.insert(env_key_1, env_val_1);
    env_map.insert(env_key_2, env_val_2);
    println!("{:?}", env_map);

    // ============== FORMAT STRINGS ==============
    let formatted = format!("Formatted: {} - {}", STATIC_MARKER_1, CONST_MARKER_1);
    println!("{}", formatted);

    // ============== ERROR MESSAGES ==============
    let error_msg = "rust error: operation failed with code 42";
    eprintln!("{}", error_msg);
}
