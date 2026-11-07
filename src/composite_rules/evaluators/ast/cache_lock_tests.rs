#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

#[test]
fn ast_cache_hit_does_not_wait_for_compiler() {
    let source = b"const value = 1;";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("cache-lock.js"))
        .cache(false)
        .open(source);
    let _ = parsed.values();
    let tree = parsed.source_ast().unwrap().tree.clone();
    let language = tree.language();
    let pattern = "(identifier) @cache_lock_hit";
    let key = (
        ast_query_language_key(&language, FileType::JavaScript),
        pattern.to_string(),
    );
    let compiler = query_compiler(&key).lock();
    let query = tree_sitter::Query::new(&language, pattern).unwrap();
    let compiled = Arc::new(CompiledAstQuery {
        literals: RequiredLiterals::of(&query, pattern),
        nodes: RequiredNodes::of(&language, &query, pattern),
        subqueries: RequiredSubqueries::default(),
        ignore_comments: false,
        deferred: DeferredPredicates::of(&query, pattern),
        root_kinds: per_root_kinds(&language, &query, pattern),
        anchors: None,
        query,
    });
    QUERY_CACHE.write().insert(key, Some(compiled.clone()));
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let hit = cached_ast_query(&tree.language(), FileType::JavaScript, pattern);
        send.send(hit).unwrap();
    });
    // Release before asserting/joining so a regression cannot deadlock the test.
    let hit = receive.recv_timeout(std::time::Duration::from_secs(5));
    drop(compiler);
    thread.join().unwrap();
    assert!(Arc::ptr_eq(
        &compiled,
        &hit.expect("cached hits must not wait for compilation")
            .unwrap()
    ));
}

#[test]
fn ast_cache_concurrent_misses_share_one_query() {
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("cache-misses.js"))
        .cache(false)
        .open(b"const value = 1;");
    let _ = parsed.values();
    let tree = parsed.source_ast().unwrap().tree;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
    let queries: Vec<_> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let tree = tree.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    cached_ast_query(
                        &tree.language(),
                        FileType::JavaScript,
                        "(identifier) @cache_concurrent_misses",
                    )
                    .unwrap()
                })
            })
            .collect();
        threads.into_iter().map(|t| t.join().unwrap()).collect()
    });
    assert!(queries.iter().all(|q| Arc::ptr_eq(&queries[0], q)));
}
