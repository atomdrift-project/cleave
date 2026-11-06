#[test]
fn directory_inventory_includes_descendants_without_prefix_siblings() {
    let ids: Vec<String> = ["item::broad", "item/key::specific", "item-else::sibling"]
        .into_iter()
        .map(String::from)
        .collect();
    let members = super::directory_trait_members(ids.iter());
    assert_eq!(members["item"].len(), 2);
    assert!(members["item"].contains("item::broad"));
    assert!(members["item"].contains("item/key::specific"));
    assert_eq!(members["item/key"].len(), 1);
    assert_eq!(members["item-else"].len(), 1);
}
