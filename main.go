package main

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"crypto/x509"
	"encoding/pem"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

func main() {
	// Create a sample XML document to sign
	xmlData, err := os.ReadFile("./data.xml")
	if err != nil {
		log.Fatal(err)
		return
	}

	doc := etree.NewDocument()
	err = doc.ReadFromBytes([]byte(xmlData))
	if err != nil {
		log.Fatal(err)
		return
	}

	// Create a private key and certificate for signing
	privateKeyPath := "./sign2.key"
	certificatePath := "./sign_dh_io_COPY_AS_PEM.pem"

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		log.Fatal(err)
		return
	}

	signer, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil {
		log.Fatal(err)
		return
	}

	// Decode PEM-encoded certificate
	// Parse the DER-encoded certificate data
	cert, err := genCertificateTags(certificate)
	if err != nil {
		log.Fatal(err)
		return
	}

	ctx, err := dsig.NewSigningContext(
		signer.PrivateKey.(crypto.Signer),
		[][]byte{
			[]byte(cert),
		},
	)

	if err != nil {
		log.Fatal(err)
		return
	}

	ctx.Hash = crypto.SHA1
	ctx.Prefix = "ds"
	ctx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()

	// Sign the XML document
	ele, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		log.Fatal(err)
		return
	}

	newdoc := etree.NewDocument()
	newdoc.AddChild(ele)
	newdoc.Indent(2)
	newdoc.WriteTo(os.Stdout)

}

func genCertificateTags(certificate []byte) (string, error) {
	block, _ := pem.Decode(certificate)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	log.Println(cert.SerialNumber)
	log.Println(cert.Subject)
	return "", nil
}

// c14n11Canonicalizer is a custom canonicalizer using Canonicalization Algorithm 1.1 (c14n11).
type c14N10ExclusiveCanonicalizer struct {
	prefixList string
	comments   bool
}

// MakeC14N10ExclusiveCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList string) dsig.Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   false,
	}
}

// MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList constructs an exclusive Canonicalizer
// from a PrefixList in NMTOKENS format (a white space separated list).
func MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList string) dsig.Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   true,
	}
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10ExclusiveCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	err := etreeutils.TransformExcC14n(el, c.prefixList, c.comments)
	if err != nil {
		return nil, err
	}

	return canonicalSerialize(el)
}

func (c *c14N10ExclusiveCanonicalizer) Algorithm() dsig.AlgorithmID {
	if c.comments {
		return dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId
	}
	return dsig.CanonicalXML10ExclusiveAlgorithmId
}

func canonicalSerialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	return doc.WriteToBytes()
}
