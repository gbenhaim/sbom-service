package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func main() {
	router := httprouter.New()
	router.GET("/sbom/*ref", sbomHandler)
	http.ListenAndServe(":8080", router)
}

func sbomHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Add("Cache-Control", "private")
	w.Header().Add("Cache-Control", "max-age=64000")

	image := strings.TrimLeft(ps.ByName("ref"), "/")

	fmt.Fprintf(os.Stderr, "querying image: %s\n", image)
	// fmt.Fprintf(os.Stderr, "namespace: %s\n", ps.ByName("namespace"))
	// take the namespace from an http header (spi auth) or query params

	downloadAndWriteSBOM(image, w)
}

func downloadAndWriteSBOM(ref string, out io.Writer) {
	_, err := download.SBOMCmd(
		context.TODO(),
		options.RegistryOptions{},
		options.SBOMDownloadOptions{},
		ref,
		out,
	)
	dieOnErr(err)
}

func dieOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
