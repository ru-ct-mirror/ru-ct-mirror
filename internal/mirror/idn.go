package mirror

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Names in these certificates are chosen by whoever asked the CA for them, and
// a summary of them ends up in a commit message that is never rewritten. So a
// name is rendered in two steps: the stored ASCII form is reduced to a byte set
// that cannot do anything to a terminal or to the message layout, and the
// Unicode reading of a punycode label is shown only when it is provably the
// same name written differently.

// maxNameRunes bounds one rendered name. A certificate may carry a SAN of
// several kilobytes; the message must stay readable either way.
const maxNameRunes = 100

// DisplayName renders one DNS name for a permanent commit message: the stored
// form, plus its Unicode reading in parentheses when the name is an IDN and the
// reading survives every check in unicodeForm.
func DisplayName(name string) string {
	ascii := asciiDisplay(name)
	if ascii == "" || ascii != name {
		// Quoted or truncated: the name is already not what the certificate
		// says byte for byte, so do not also claim to read it.
		return ascii
	}
	u, ok := unicodeForm(name)
	if !ok {
		return ascii
	}
	return ascii + " (" + u + ")"
}

// asciiDisplay reduces a stored name to something safe to put on a line of its
// own. Names are lowercased before they get here, so the allowed set is small;
// anything else is quoted, and anything long is cut.
func asciiDisplay(name string) string {
	if name == "" {
		return ""
	}
	safe := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == '*':
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	out := name
	if !safe {
		// QuoteToASCII, not Quote: Quote passes printable non-ASCII through
		// unescaped, which is the hole this is here to close.
		out = strconv.QuoteToASCII(name)
	}
	return truncate(out)
}

func truncate(s string) string {
	if utf8.RuneCountInString(s) <= maxNameRunes {
		return s
	}
	n := 0
	for i := range s {
		if n == maxNameRunes-1 {
			return s[:i] + "…"
		}
		n++
	}
	return s
}

// unicodeForm decodes the punycode labels of an all-ASCII name. It reports
// false unless the reading is unambiguous: every decoded label re-encodes to
// exactly the label that was stored, the result really is non-ASCII, every rune
// is safe to print, and all letters come from one script.
func unicodeForm(name string) (string, bool) {
	labels := strings.Split(name, ".")
	idn := false
	for i, l := range labels {
		if !strings.HasPrefix(l, "xn--") {
			continue
		}
		u, err := punycodeDecode(l[len("xn--"):])
		if err != nil {
			return "", false
		}
		enc, err := punycodeEncode(u)
		if err != nil || "xn--"+enc != l {
			// Non-canonical punycode: two spellings of one label, or a decoder
			// disagreement. Either way, do not print a reading.
			return "", false
		}
		if u == "" || isASCII(u) {
			// A punycode label that decodes to ASCII, or to nothing, is not an
			// IDN label at all: xn--abc- is its own DNS name and is not another
			// spelling of abc. The test has to be per label, because one honest
			// label elsewhere in the name would otherwise carry it through.
			return "", false
		}
		labels[i] = u
		idn = true
	}
	if !idn {
		return "", false
	}
	out := strings.Join(labels, ".")
	if out == name || isASCII(out) {
		return "", false
	}
	if utf8.RuneCountInString(out) > maxNameRunes {
		return "", false
	}
	for _, r := range out {
		if !safeToPrint(r) {
			return "", false
		}
	}
	if !singleScriptLabels(out) {
		return "", false
	}
	return out, true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// safeToPrint rejects everything that could make a decoded name lie about
// itself in a terminal, a diff or a web view.
func safeToPrint(r rune) bool {
	if !unicode.IsPrint(r) {
		return false
	}
	for _, t := range []*unicode.RangeTable{
		unicode.Cc,                      // controls, ESC
		unicode.Cf,                      // ZWJ/ZWNJ, LRM/RLM, isolates, BOM
		unicode.Cs,                      // surrogates: punycode can decode into them
		unicode.Co,                      // private use
		unicode.Bidi_Control,            // spelled out although Cf covers it
		unicode.Join_Control,            //
		unicode.Variation_Selector,      //
		unicode.Noncharacter_Code_Point, //
		unicode.Deprecated,              //
		// Hangul fillers and friends: letters by category, printable by Go,
		// and blank on screen, so a label of them reads as nothing at all.
		unicode.Other_Default_Ignorable_Code_Point,
		unicode.White_Space, // NBSP, ideographic space
		// Every mark, spacing ones included: they attach to the character
		// before them, and singleScript does not see them because they are not
		// letters, so an a with a Devanagari vowel sign would otherwise read
		// as a plain Latin name.
		unicode.M,
	} {
		if unicode.Is(t, r) {
			return false
		}
	}
	// The parentheses frame the reading in the rendered line.
	return r != '(' && r != ')'
}

// singleScriptLabels reports whether every label of a name is written in one
// script. It is what stops аpple.ru, Cyrillic а and Latin pple, from being
// printed as if it were the English word. The test is per label, not per name:
// a Cyrillic label under an ASCII top-level domain is ordinary here, and the
// mirror holds such names today. A label that is confusable as a whole is not
// caught by this, and is not meant to be: the stored form is always printed
// next to the reading, so nothing can hide behind it.
func singleScriptLabels(name string) bool {
	for _, l := range strings.Split(name, ".") {
		if !singleScript(l) {
			return false
		}
	}
	return true
}

func singleScript(s string) bool {
	script := ""
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		found := ""
		for name, table := range unicode.Scripts {
			if name == "Common" || name == "Inherited" {
				continue
			}
			if unicode.Is(table, r) {
				found = name
				break
			}
		}
		if found == "" {
			return false
		}
		if script == "" {
			script = found
		} else if script != found {
			return false
		}
	}
	return true
}

// RFC 3492 punycode, ported from the decoder in site/index.html so that the
// commit messages and the published site read the same names the same way. The
// parameters are the ones the RFC fixes for IDNA.
const (
	pyBase     = 36
	pyTMin     = 1
	pyTMax     = 26
	pySkew     = 38
	pyDamp     = 700
	pyInitBias = 72
	pyInitN    = 128
	// pyMaxDelta keeps the arithmetic far below the point where int could
	// overflow on any platform Go supports.
	pyMaxDelta = 1 << 30
)

var errPunycode = errors.New("punycode: malformed label")

func pyAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pyBase-pyTMin)*pyTMax)/2 {
		delta /= pyBase - pyTMin
		k += pyBase
	}
	return k + (pyBase-pyTMin+1)*delta/(delta+pySkew)
}

// punycodeDecode decodes the part of a label that follows the xn-- prefix.
func punycodeDecode(input string) (string, error) {
	if !isASCII(input) {
		return "", errPunycode
	}
	var out []rune
	n := rune(pyInitN)
	i, bias := 0, pyInitBias
	b := strings.LastIndex(input, "-")
	for j := 0; j < b; j++ {
		out = append(out, rune(input[j]))
	}
	pos := 0
	if b > 0 {
		pos = b + 1
	}
	for pos < len(input) {
		oldi := i
		w := 1
		for k := pyBase; ; k += pyBase {
			if pos >= len(input) {
				return "", errPunycode
			}
			digit, err := pyDigit(input[pos])
			if err != nil {
				return "", err
			}
			pos++
			if digit > (pyMaxDelta-i)/w {
				return "", errPunycode
			}
			i += digit * w
			t := k - bias
			if t < pyTMin {
				t = pyTMin
			} else if t > pyTMax {
				t = pyTMax
			}
			if digit < t {
				break
			}
			if w > pyMaxDelta/(pyBase-t) {
				return "", errPunycode
			}
			w *= pyBase - t
		}
		length := len(out) + 1
		bias = pyAdapt(i-oldi, length, oldi == 0)
		if i/length > int(unicode.MaxRune-n) {
			return "", errPunycode
		}
		n += rune(i / length)
		i %= length
		if n > unicode.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			// A surrogate would turn into U+FFFD on the way into a string and
			// the round-trip check would then reject the label anyway; refuse
			// it here so that is a decision rather than an accident.
			return "", errPunycode
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = n
		i++
	}
	return string(out), nil
}

// punycodeEncode is the inverse, used only to prove that a decoded label is the
// one canonical spelling of what was stored.
func punycodeEncode(s string) (string, error) {
	runes := []rune(s)
	var out []byte
	basic := 0
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
			basic++
		}
	}
	h := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n := rune(pyInitN)
	delta, bias := 0, pyInitBias
	for h < len(runes) {
		m := rune(unicode.MaxRune) + 1
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		if int(m-n) > (pyMaxDelta-delta)/(h+1) {
			return "", errPunycode
		}
		delta += int(m-n) * (h + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
				if delta > pyMaxDelta {
					return "", errPunycode
				}
			}
			if r != n {
				continue
			}
			q := delta
			for k := pyBase; ; k += pyBase {
				t := k - bias
				if t < pyTMin {
					t = pyTMin
				} else if t > pyTMax {
					t = pyTMax
				}
				if q < t {
					break
				}
				out = append(out, pyEncodeDigit(t+(q-t)%(pyBase-t)))
				q = (q - t) / (pyBase - t)
			}
			out = append(out, pyEncodeDigit(q))
			bias = pyAdapt(delta, h+1, h == basic)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out), nil
}

func pyDigit(c byte) (int, error) {
	switch {
	case c >= '0' && c <= '9':
		return int(c-'0') + 26, nil
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), nil
	case c >= 'a' && c <= 'z':
		return int(c - 'a'), nil
	}
	return 0, errPunycode
}

func pyEncodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
