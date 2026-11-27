package ingest

import (
	"context"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// masked replaces every span Mask hides.
const masked = "[masked]"

// mark is a joined line break in a view (see views): a private-use rune, which Clean drops.
const mark = '\uE000'

// Clean is s without control, format, private-use and filler characters. Newlines and tabs stay, and every line break
// is \n.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n', r == '\v', r == '\f', r == '\r', r == 0x85, r == 0x2028, r == 0x2029:
			return '\n'
		case r == '\t':
			return r
		case !unicode.IsGraphic(r), unicode.Is(unicode.Variation_Selector, r), unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return -1
		}
		return r
	}, strings.ReplaceAll(s, "\r\n", "\n"))
}

// Mask is Clean(s) with credentials replaced. It stops with ctx's error once ctx is done.
func Mask(ctx context.Context, s string) (string, error) {
	base := []rune(Clean(s))
	hide := make([]bool, len(base)+1)
	for n, v := range views(base) {
		text, at := v.text()
		for _, r := range rules {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if n >= 2 && !r.joined {
				continue
			}
			r.find(text, func(from, to int) {
				end := int(v[at[to-1]].to)
				for end < len(base) && !unicode.IsSpace(base[end]) && !strings.ContainsRune(stops, base[end]) {
					end++
				}
				for i := int(v[at[from]].from); i < end; i++ {
					hide[i] = true
				}
			})
		}
	}
	var b strings.Builder
	for i, r := range base {
		switch {
		case !hide[i]:
			b.WriteRune(r)
		case !hide[i+1]:
			b.WriteString(masked)
		}
	}
	return b.String(), nil
}

// stops are the characters a hidden span does not grow past.
const stops = "\"'`<>()[]{},;|&@#?"

// rule hides the groups of its match (the whole match when it has none), or what each finds in them, where accept takes
// the match and the span. A joined rule also reads the joined views.
type rule struct {
	re     *regexp.Regexp
	each   *regexp.Regexp
	joined bool
	accept func(match, span string) bool
}

func (r rule) find(text string, hide func(from, to int)) {
	take := func(match string, from, to int) {
		if from < to && (r.accept == nil || r.accept(match, text[from:to])) {
			hide(from, to)
		}
	}
	for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
		match := text[m[0]:m[1]]
		if len(m) == 2 {
			m = []int{m[0], m[1], m[0], m[1]}
		}
		for g := 2; g < len(m); g += 2 {
			switch {
			case m[g] < 0:
			case r.each == nil:
				take(match, m[g], m[g+1])
			default:
				for _, e := range r.each.FindAllStringSubmatchIndex(text[m[g]:m[g+1]], -1) {
					take(match, m[g]+e[len(e)-2], m[g]+e[len(e)-1])
				}
			}
		}
	}
}

// cell is one rune of a view and the base runes [from, to) it stands for; a view is the text in one reading.
type (
	cell struct {
		r        rune
		from, to int32
	}
	view []cell
)

// text is the view as a string, and per byte of it the cell it belongs to (one entry more, for the end).
func (v view) text() (string, []int32) {
	var b strings.Builder
	b.Grow(len(v))
	at := make([]int32, 0, len(v)+1)
	for i, c := range v {
		b.WriteRune(c.r)
		for len(at) < b.Len() {
			at = append(at, int32(i))
		}
	}
	return b.String(), append(at, int32(len(v)))
}

// views are the readings the rules run on: the text as it is; folded and unescaped; and that with line breaks, quotes
// and emphasis joined, once into nothing and once into mark.
func views(base []rune) []view {
	raw := make(view, 0, len(base))
	plain := make(view, 0, len(base))
	for i, r := range base {
		raw = append(raw, cell{r, int32(i), int32(i + 1)})
		plain = append(plain, folded(string(r), int32(i), int32(i+1))...)
	}
	for range 4 {
		next, changed := unescape(plain)
		plain = next
		if !changed {
			break
		}
	}
	return []view{raw, plain, join(plain, 0), join(plain, mark)}
}

// folded is s as cells of [from, to): in ASCII where a rune has such a form, without what Clean
// drops or a mark that only combines.
func folded(s string, from, to int32) view {
	var v view
	for _, r := range Clean(s) {
		a, ok := lookalikes[r]
		switch {
		case ok:
			r = a
		case unicode.Is(unicode.Mn, r):
			continue
		case unicode.Is(unicode.Zs, r):
			r = ' '
		case r >= utf8.RuneSelf:
			if n := norm.NFKC.String(string(r)); len(n) == 1 {
				r = rune(n[0])
			}
		}
		v = append(v, cell{r, from, to})
	}
	return v
}

// lookalikes are the Latin letters folded reads some others as.
var lookalikes = func() map[rune]rune {
	m := map[rune]rune{}
	from, to := []rune("авгеёһіїјкӏмнорѕтуѵхԁԛѡАВЕЅІЈКМНОРСТУХZԌсαβγεηικνορστυχωΑΒΕΖΗΙΚΜΝΟΡΤΥΧϲ"), []rune("abreehiijklmhopstyvxdqwABESIJKMHOPCTYXZGcabyenikvopotuxwABEZHIKMNOPTYXc")
	for i, r := range from {
		m[r] = to[i]
	}
	return m
}()

var escapes = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2})+|(?:\\u[0-9A-Fa-f]{4})+|(?:\\x[0-9A-Fa-f]{2})+|\\["'/\\bfnrt]|&#?[0-9A-Za-z]{2,8};`)

func unescape(v view) (view, bool) {
	text, at := v.text()
	var out view
	last, changed := 0, false
	for _, m := range escapes.FindAllStringIndex(text, -1) {
		e := text[m[0]:m[1]]
		dec := decode(e)
		if dec == e {
			continue
		}
		out = append(out, v[at[last]:at[m[0]]]...)
		out = append(out, folded(dec, v[at[m[0]]].from, v[at[m[1]-1]].to)...)
		last, changed = m[1], true
	}
	return append(out, v[at[last]:]...), changed
}

func decode(e string) string {
	switch {
	case e[0] == '%':
		return hexBytes(e, 3)
	case e[0] == '&':
		return html.UnescapeString(e)
	case e[1] == 'x':
		return hexBytes(e, 4)
	case e[1] == 'u':
		var b strings.Builder
		for i := 0; i < len(e); i += 6 {
			n, _ := strconv.ParseUint(e[i+2:i+6], 16, 16) // four hex digits: cannot fail
			b.WriteRune(rune(n))
		}
		return b.String()
	case e[1] == 'r':
		return "" // of \r\n, one break
	case strings.ContainsRune("bfnt", rune(e[1])):
		return "\n"
	}
	return e[1:]
}

// hexBytes decodes escapes of n characters each that end in two hex digits; bytes that are not UTF-8 are dropped.
func hexBytes(e string, n int) string {
	var b []byte
	for i := n; i <= len(e); i += n {
		x, _ := strconv.ParseUint(e[i-2:i], 16, 8) // two hex digits: cannot fail
		b = append(b, byte(x))
	}
	return strings.ToValidUTF8(string(b), "")
}

var breaks = regexp.MustCompile("[\"'`]+\\s*[+.&,]?\\s*[\"'`]+|[\"'`*\\\\]+|[ \\t]*\\n[\\s>|#]*")

// join replaces single line breaks, quotes, emphasis and quoted concatenations with r, or with nothing when r is 0.
func join(v view, r rune) view {
	text, at := v.text()
	var out view
	last := 0
	for _, m := range breaks.FindAllStringIndex(text, -1) {
		if strings.Count(text[m[0]:m[1]], "\n") > 1 {
			continue // a blank line ends a paragraph
		}
		out = append(out, v[at[last]:at[m[0]]]...)
		if r != 0 {
			out = append(out, cell{r, v[at[m[0]]].from, v[at[m[1]-1]].to})
		}
		last = m[1]
	}
	return append(out, v[at[last]:]...)
}

const (
	tok        = `[0-9A-Za-z_\-\x{E000}]`
	passWord   = `pass(?:word|wd|phrase|code)s?|pwd|mdp|mot[ _\-]de[ _\-]passe`
	secretWord = `(?:` + passWord + `|secrets?|tokens?|credentials?|creds|jeton|connection[ _\-]?string|` +
		`(?:api|access|private|secret|signing|encryption|master|shared|deploy|license|hmac|auth)[ _.\-]?keys?)`
	// name ends in a secretWord; a query string's names have their own rule.
	name   = `(?:^|[^\w.?&\-])["'` + "`" + `*_]{0,3}[\w.\-]*` + secretWord + `(?:_?[0-9]+)?`
	emph   = "[\"'`*_\\]\\\\]{0,4}"
	equals = emph + `(?:[ \t]*\([^)\n]*\))?(?:[ \t]+(?:for|of|on|in|pour|de|du)[ \t]+[^\s:=|]+(?:[ \t][^\s:=|]+)?)?(?:[ \t]+(?:is|was|are|est))?` + emph +
		`[ \t]*(?::=|=>|->|→|[:=]|\]\()[ \t]*[*_]{0,3}[ \t]*`
	quoted = `\\?(?:"([^"\s,.;)][^"\n]*)"?|'([^'\s,.;)][^'\n]*)'?|` + "`([^`\\s,.;)][^`\\n]*)`?)"
	value  = `(?:` + quoted + `(?:[ \t]*\+[ \t]*\n?[ \t]*` + quoted + `)?|([^\s"'` + "`" + `]+))`
)

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var rules = []rule{
	{re: re(`(?is)-{3,}\s*BEGIN[^\-]{0,60}PRIVATE[^\-]{1,60}-{3,}.*?(?:-{3,}\s*END[^\-]{1,60}-{3,}|\z)`)},
	{re: re(`(?is)PuTTY-User-Key-File.*`)},
	{re: re(`(?i)(?:gh[opusr]_|github_pat_|gl(?:pat|ptt|cbt|dt|rt|rtr|soat|ft|ffct|imt|agent|oas)-|gl(?:c|sa)_|xox[a-z][.\-]|xapp-|` +
		`[sprw]k_(?:live|test|prod)_|whsec_|npm_|pypi-|dckr_(?:pat|oat)_|do[oprt]_v1_|hf_|ya29\.|gocspx-|hv[sbr]\.|tskey-|` +
		`lin_(?:api|oauth)_|ntn_|xai-|gsk_|r8_|shp(?:at|ca|pa|ss)_|rubygems_|pmak-|age-secret-key-|sk-ant-|sk-proj-|sg\.)(` + tok + `{8,})`),
		joined: true, accept: opaque},
	{re: re(`(?:^|[^0-9A-Za-z])sk-(` + tok + `{16,})`), joined: true, accept: opaque},
	{re: re(`(?:^|[^0-9A-Za-z.])(?:st|ua)\.([0-9A-Za-z_\-.\x{E000}]{12,})`), joined: true, accept: opaque},
	{re: re(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AROA|AIDA)[A-Z0-9\x{E000}]{16,}`), joined: true},
	{re: re(`AIza` + tok + `{20,}`), joined: true},
	{re: re(`eyJ[0-9A-Za-z_\-\x{E000}]{8,}(?:\.[0-9A-Za-z_\-=\x{E000}]*)*`), joined: true},
	{re: re(`\b[0-9]{8,12}:` + tok + `{30,}`), joined: true},
	{re: re(`\b[MNO][0-9A-Za-z_\-\x{E000}]{22,}\.` + tok + `{6}\.` + tok + `{20,}`), joined: true},
	{re: re(`(?i)discord(?:app)?\.com/api/(?:v[0-9]+/)?webhooks/([^\s"'<>)]+)`), joined: true},
	{re: re(`(?i)hooks\.slack\.com/services/([^\s"'<>)]+)`), joined: true},
	{re: re(`(?i)[a-z][0-9a-z+.\-]*://([^\s/@:"'<>]*:[^\s@"'<>]+)@`), accept: literal},
	{re: re(`(?i)\b(?:https?|git)://([^\s/@:"'<>]+)@`), accept: said},
	{re: re(`(?i)[?&;][\w.\-]*(?:token|secret|passw(?:or)?d|pwd|api[_\-]?key|access[_\-]?key|signature|\bsig|credential)=([^&#\s"'` + "`" + `<>)\]]+)`)},
	{re: re(`(?i)\bbearer[ \t:="']+([\w.~+/=\-\x{E000}]{12,})`), joined: true, accept: digit},
	{re: re(`(?i)\bauthorization["']?[ \t]*[:=][ \t]*["']?(?:(?:basic|bearer|token|digest|apikey)[ \t]+)?([^\s"',;]{8,})`), accept: digit},
	{re: re(`(?i)\bcookie:[ \t]*([^\n]+)`), each: re(`=([^\s;]{8,})`), accept: digit},
	{re: re(`(?i)(?:^|\s)--[\w\-]*` + secretWord + `[= ]["']?([^\s"'\-][^\s"']*)`), accept: valued},
	{re: re(`(?i)\bcurl\b[^\n]*\s(?:-u|--user)[ =]*["']?([^\s:"']+:[^\s"']+)`), accept: literal},
	{re: re(`(?i)<[\w:\-]*` + secretWord + `[^<>]*>([^<\s]+)<`), accept: valued},
	{re: re(`(?i)` + name + equals + value), accept: valued},
	{re: re(`(?im)` + name + emph + `[ \t]*[:=]?` + emph + `[ \t]*\n(?:[ \t>]*\n)?[ \t>]*(?:(?:` + "`{3}" + `|~{3})[\w\-]*[ \t]*\n[ \t>]*)?(\S+)[ \t]*$`), accept: said},
	{re: re(`(?i)` + name + emph + `[ \t]*:[ \t]*\n((?:[ \t]*-[ \t]+[^\n]*(?:\n|\z))+)`), each: re(`-[ \t]+["'` + "`" + `]?([^\s"'` + "`" + `]+)["'` + "`" + `]?[ \t]*(?:\n|\z)`), accept: valued},
	{re: re(`(?i)` + name + emph + `[ \t]*[:=][ \t]*\[([^\]]*)\]`), each: re(`["']([^"']+)["']`), accept: valued},
	{re: re(`(?i)` + name + emph + `[ \t]*:[ \t]*[|>][\-+]?[ \t]*\n((?:[ \t]+[^\n]*(?:\n|\z))+)`), each: re(`\S+`), accept: valued},
	{re: re(`(?i)\|[ \t*` + "`" + `]*[\w.\- ]*` + secretWord + `[ \t*` + "`" + `]*\|[ \t*` + "`" + `]*([^\s|*` + "`" + `]+)[ \t*` + "`" + `]*\|`), accept: said},
	{re: re(`(?i)\b(?:` + secretWord + `)` + emph + `[ \t]+(?:(?:has[ \t]+been|was|is|got)[ \t]+)?(?:is|was|are|est|=|changed[ \t]+to|set[ \t]+to|reset[ \t]+to|rotated[ \t]+to|updated[ \t]+to)` +
		`(?:[ \t]+(?:now|currently|still))?:?\s+["'` + "`" + `*]{0,2}([^\s"'` + "`" + `*]+)`), accept: said},
	{re: re(`(?i)\b(?:` + passWord + `)[ \t]+(?:["'` + "`" + `]([^\s"'` + "`" + `]+)["'` + "`" + `]|([^\s"'` + "`" + `]+))`), accept: said},
	{re: re(`(?i)(?:\w+[ \t_\-]+)?\bcode` + emph + `(?:[ \t]*[:=]|[ \t]+is)[ \t]*["'` + "`" + `*]{0,2}([0-9]{3}[ \-]?[0-9]{3,5})(?:[^\w.\-]|\z)`), accept: oneTime},
	{re: re(`(?i)\b(?:pin|otp)` + emph + `(?:[ \t]+code)?(?:[ \t]*[:=]|[ \t]+is)?[ \t]*["'` + "`" + `*]{0,2}([0-9]{3}[ \-]?[0-9]{1,5})(?:[^\w.\-]|\z)`)},
	{re: re(`[0-9A-Za-z+/_=\-]{32,}`), accept: random},
}

var (
	placeholder = re(`(?i)^(?:[<$%{\[(*&.~≥≤]|/|\w+://|[\w.]+\(|[\w\-]+=.|[hrep]s(?:256|384|512)\b|x{3,}|redacted|masked|null|none|true|false)|\$[{(]|\{\{`)
	constant    = re(`^[A-Z][A-Z0-9]*(?:[_/][A-Z0-9*<>]+)+[.,]?$`)
	words       = re(`^(?:[A-Za-z]+[ \-_./→]+)+[A-Za-z]+$`)
	number      = re(`^(?:v?[0-9]+(?:[.,:/\-][0-9]+)*|[0-9.,]+(?:%|[a-zA-Z]{1,3}))$`)
	passName    = re(`(?i)(?:` + passWord + `|pin|otp)`)
	notCode     = re(`(?i)^(?:exit|status|error|http|response|return|returned|reason|country|area|zip|postal|product|source|version)[ \t_\-]`)
)

func literal(_, s string) bool { return !placeholder.MatchString(s) }

func digit(_, s string) bool { return strings.ContainsAny(s, "0123456789") && literal("", s) }

// opaque takes a token's rest.
func opaque(_, s string) bool {
	return digit("", s) || strings.IndexFunc(s, unicode.IsUpper) > 0 && strings.IndexFunc(s, unicode.IsLower) >= 0
}

// valued takes a name's value.
func valued(match, s string) bool {
	if !literal("", s) {
		return false
	}
	s = strings.Trim(s, " \"'`*_.,;:!?()[]{}")
	n := utf8.RuneCountInString(s)
	pass := passName.MatchString(match)
	if constant.MatchString(s) || !pass && words.MatchString(s) {
		return false
	}
	if number.MatchString(s) {
		return n >= 4 && pass
	}
	return n >= 12 || n >= 4 && digit("", s)
}

// said is valued, in a sentence.
func said(match, s string) bool { return digit("", s) && valued(match, s) }

func oneTime(match, _ string) bool { return !notCode.MatchString(match) }

var (
	parts   = re(`[0-9A-Za-z]+`)
	plainID = re(`^(?:[0-9a-z]+|[0-9A-Z]+|[A-Za-z]+)$`)
)

// random takes a run that looks generated.
func random(_, run string) bool {
	var upper, lower, digits, turns, letters, longest, stretch int
	for _, part := range parts.FindAllString(run, -1) {
		if plainID.MatchString(part) && len(part) > 1 {
			continue
		}
		var last rune
		for _, r := range part {
			c := 'd'
			switch {
			case r >= 'a':
				c = 'l'
				lower++
			case r >= 'A':
				c = 'u'
				upper++
			default:
				digits++
			}
			letters++
			if last != 0 && c != last && (last != 'u' || c != 'l') {
				turns++
			}
			if stretch++; c != 'l' || last != 'l' {
				stretch = 1
			}
			longest = max(longest, stretch)
			last = c
		}
	}
	return upper > 0 && lower > 0 && digits > 0 && letters >= 28 && (longest <= 4 || turns*100 >= letters*33)
}
