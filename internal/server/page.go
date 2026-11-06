package server

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Страница зависит от PSK, поэтому у разных серверов нет одного и того же HTML,
// по которому их можно было бы узнать одним запросом.
func newPage(psk []byte) []byte {
	sum := sha256.Sum256(append([]byte("veil-v1-page"), psk...))
	titles := []string{"Field notes", "Workshop log", "Garden diary", "Studio hours", "Harbor notes"}
	leads := []string{
		"Short records from the workbench, kept in one place.",
		"A quiet log of small jobs, materials, and weather.",
		"Notes taken while projects are still unfinished.",
		"Dates, measurements, and things to revisit later.",
	}
	notes := []string{
		"Oak sample dried two days longer than expected.",
		"North window light is better after four.",
		"Order more graphite before the end of the month.",
		"The third shelf still needs a stronger bracket.",
	}
	title := titles[int(sum[0])%len(titles)]
	lead := leads[int(sum[1])%len(leads)]
	note := notes[int(sum[2])%len(notes)]
	hue := int(sum[3]) % 360
	var b strings.Builder
	fmt.Fprintf(&b, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{margin:0;font:18px/1.5 Georgia,serif;background:#f6f4ef;color:#222}
main{max-width:38rem;margin:4rem auto;padding:0 1.25rem}
h1{font-weight:normal;color:hsl(%d,35%%,28%%)}
</style>
</head>
<body>
<main>
<h1>%s</h1>
<p>%s</p>
<p>%s</p>
</main>
</body>
</html>
`, title, hue, title, lead, note)
	return []byte(b.String())
}
