use std::fs;
use cleave::strings::StringExtractor;

fn main() {
    let data = fs::read("/Users/t/data/dissect/malware/cpp/2026.Luckyware/LuckywareSite/Data/vendor/imagesloaded/assets/2D333F_1_0.woff2").unwrap();
    let extractor = StringExtractor::default();
    let strings = extractor.extract_smart(&data, None);
    for s in strings {
        if s.value.contains("158") || s.offset == 13222 {
            println!("Offset: {}, String: {}, Kind: {:?}", s.offset, s.value, s.kind);
        }
    }
}
