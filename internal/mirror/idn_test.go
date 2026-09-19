package mirror

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestDisplayNameReadsIDNs(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The example the README and the site use.
		{"xn--d1aqf.xn--p1ai", "xn--d1aqf.xn--p1ai (дом.рф)"},
		// A Cyrillic label under an ASCII top-level domain: the mirror holds
		// such names, and they are not a mixed-script trick.
		{"xn--d1aqf.su", "xn--d1aqf.su (дом.su)"},
		// Arabic is a script, not a control character: read it.
		{"xn--mgbh0fb.ru", "xn--mgbh0fb.ru (مثال.ru)"},
		// Plain names and wildcards are passed through untouched.
		{"gosuslugi.ru", "gosuslugi.ru"},
		{"*.mos.ru", "*.mos.ru"},
		{"", ""},
	} {
		if got := DisplayName(tc.in); got != tc.want {
			t.Errorf("DisplayName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayNameWithholdsDoubtfulReadings(t *testing.T) {
	for _, name := range []string{
		"xn--abc-.ru",       // decodes to pure ASCII: always a trick
		"xn--ib9b.ru",       // decodes into a surrogate
		"xn--.ru",           // nothing to decode
		"xn--a b.ru",        // not a label at all
		"xn--0000000000.ru", // malformed digits
		"xn--vhk.ru",        // U+3164 HANGUL FILLER: a letter that shows nothing
		"xn--osd.ru",        // U+115F HANGUL CHOSEONG FILLER
		"xn--cl7c.ru",       // U+FFA0 HALFWIDTH HANGUL FILLER
		"xn--tua.ru",        // U+034F COMBINING GRAPHEME JOINER
		"xn--a-6wd.ru",      // Latin a with a Devanagari spacing vowel sign
		"xn--a-1k8q.ru",     // Latin a with a musical combining stem
		// An ASCII-only or empty label must not be carried through by an
		// honest label beside it: these are their own DNS names.
		"xn--abc-.xn--p1ai",
		"xn--.xn--p1ai",
	} {
		got := DisplayName(name)
		if strings.Contains(got, "(") {
			t.Errorf("DisplayName(%q) = %q, want no reading", name, got)
		}
	}
	// Cyrillic а with Latin pple: one label, two scripts.
	mixed := "xn--pple-43d.com"
	if got := DisplayName(mixed); strings.Contains(got, "(") {
		t.Errorf("DisplayName(%q) = %q, want no reading", mixed, got)
	}
	if u, _ := punycodeDecode("pple-43d"); u != "аpple" {
		t.Fatalf("the mixed-script fixture decodes to %q, so it no longer tests what it says", u)
	}
}

func TestAsciiDisplayFlattensHostileNames(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"newline", "a.ru\nsync 2026-01-01T00:00:00Z: 0 entries"},
		{"carriage return", "a.ru\rsync"},
		{"escape", "a.ru\x1b[31m"},
		{"non-ASCII bytes", "\xd0\xb4.ru"},
		{"space", "a b.ru"},
	} {
		got := asciiDisplay(tc.in)
		if strings.ContainsAny(got, "\n\r\x1b") {
			t.Errorf("%s: asciiDisplay(%q) = %q, still holds a control character", tc.name, tc.in, got)
		}
		if !isASCII(got) {
			t.Errorf("%s: asciiDisplay(%q) = %q, not ASCII", tc.name, tc.in, got)
		}
		if got == tc.in {
			t.Errorf("%s: asciiDisplay(%q) passed the name through unquoted", tc.name, tc.in)
		}
	}
	long := strings.Repeat("a", 300) + ".ru"
	got := asciiDisplay(long)
	if n := utf8.RuneCountInString(got); n != maxNameRunes {
		t.Errorf("a %d-rune name rendered as %d runes, want %d", utf8.RuneCountInString(long), n, maxNameRunes)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated name does not say so: %q", got)
	}
	// A name that had to be quoted or cut is never also given a reading.
	if d := DisplayName(long); strings.Contains(d, "(") {
		t.Errorf("DisplayName of a truncated name offers a reading: %q", d)
	}
}

func TestSafeToPrintRejectsDeceptiveRunes(t *testing.T) {
	for _, r := range []rune{
		0x0000, 0x001b, // NUL, ESC
		0x200b, 0x200d, // zero width space, zero width joiner
		0x202e, 0x2066, // right-to-left override, isolate
		0xfeff,         // byte order mark
		0x00a0, 0x3000, // no-break and ideographic space
		0x0301,   // combining acute
		0xe000,   // private use
		0xfffe,   // noncharacter
		0x3164,   // Hangul filler: a letter that occupies no space
		0x115f,   // Hangul choseong filler
		0x1160,   // Hangul jungseong filler
		0xffa0,   // halfwidth Hangul filler
		0x093e,   // Devanagari vowel sign: a mark that takes up space
		0x1d165,  // musical combining stem
		'(', ')', // would break the framing
	} {
		if safeToPrint(r) {
			t.Errorf("safeToPrint(%U) = true", r)
		}
	}
	for _, r := range []rune{'д', 'م', '中', 'a', '-', '9'} {
		if !safeToPrint(r) {
			t.Errorf("safeToPrint(%U) = false, want true", r)
		}
	}
}

func TestPunycodeRoundTrip(t *testing.T) {
	for _, s := range []string{"дом", "рф", "бücher", "مثال", "中文", "a1-b"} {
		enc, err := punycodeEncode(s)
		if err != nil {
			t.Fatalf("encode %q: %v", s, err)
		}
		back, err := punycodeDecode(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if back != s {
			t.Errorf("round trip of %q gave %q via %q", s, back, enc)
		}
	}
}

func FuzzPunycodeDecode(f *testing.F) {
	for _, s := range []string{"d1aqf", "p1ai", "bcher-kva", "", "-", "abc-", "ib9b", "0000000000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := punycodeDecode(in)
		if err != nil {
			return
		}
		for _, r := range out {
			if r > unicode.MaxRune || (r >= 0xD800 && r <= 0xDFFF) {
				t.Fatalf("decode(%q) produced %U", in, r)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("decode(%q) produced invalid UTF-8", in)
		}
		// Whatever comes out, the rendered name stays on one line.
		if d := DisplayName("xn--" + in + ".ru"); strings.ContainsAny(d, "\n\r") {
			t.Fatalf("DisplayName of %q spans lines: %q", in, d)
		}
	})
}
