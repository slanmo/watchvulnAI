package platform

func messageChunks(text string, size int) []string {
	r := []rune(text)
	out := []string{}
	for len(r) > 0 {
		n := size
		if n > len(r) {
			n = len(r)
		}
		out = append(out, string(r[:n]))
		r = r[n:]
	}
	return out
}
