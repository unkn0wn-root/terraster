package pool

import (
	"net/url"
	"strings"
)

// helper function to concatenate the target path with the request path.
// ensures that there are no duplicate slashes.
func joinURLPath(parsedUrl, reqUrl *url.URL) (path, rawpath string) {
	// parsedUrl from service
	p := parsedUrl.EscapedPath()
	if p == "" {
		p = "/"
	}

	// request URL
	r := reqUrl.EscapedPath()
	// ensure that there is exactly one '/' between the paths
	if strings.HasSuffix(p, "/") && strings.HasPrefix(r, "/") {
		path = p + r[1:]
		rawpath = p + r[1:]
	} else if !strings.HasSuffix(p, "/") && !strings.HasPrefix(r, "/") {
		path = p + "/" + r
		rawpath = p + "/" + r
	} else {
		path = p + r
		rawpath = p + r
	}

	return
}
