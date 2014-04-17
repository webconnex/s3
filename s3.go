package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type S3 struct {
	Scheme    string
	Host      string
	Bucket    string
	AccessKey string
	SecretKey string
}

func (s3 *S3) SignedURL(path string, expires time.Time) string {
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	u := url.URL{
		Scheme: s3.Scheme,
		Host:   s3.Host,
		Path:   "/" + s3.Bucket + path,
	}
	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}
	if len(u.Host) == 0 {
		u.Host = "s3.amazonaws.com"
	}
	q := url.Values{}
	q.Set("AWSAccessKeyId", s3.AccessKey)
	q.Set("Expires", strconv.FormatInt(expires.Unix(), 10))
	q.Set("Signature", s3.sign(s3.payload("GET", u.Path, nil, nil, expires)))
	u.RawQuery = q.Encode()
	return u.String()
}

func (s3 *S3) SignedUploadURL(path, contentType string, expires time.Time) string {
	if len(path) > 0 && path[0] != '/' {
		path = "/" + path
	}
	u := url.URL{
		Scheme: s3.Scheme,
		Host:   s3.Host,
		Path:   "/" + s3.Bucket + path,
	}
	if len(u.Scheme) == 0 {
		u.Scheme = "https"
	}
	if len(u.Host) == 0 {
		u.Host = "s3.amazonaws.com"
	}
	h := http.Header{}
	h.Set("Content-Type", contentType)
	q := url.Values{}
	q.Set("AWSAccessKeyId", s3.AccessKey)
	q.Set("Expires", strconv.FormatInt(expires.Unix(), 10))
	q.Set("Signature", s3.sign(s3.payload("PUT", u.Path, nil, h, expires)))
	u.RawQuery = q.Encode()
	return u.String()
}

var querySign = [...]string{
	"acl",
	"location",
	"logging",
	"notification",
	"partNumber",
	"policy",
	"requestPayment",
	"torrent",
	"uploadId",
	"uploads",
	"versionId",
	"versioning",
	"versions",
	"response-content-type",
	"response-content-language",
	"response-expires",
	"response-cache-control",
	"response-content-disposition",
	"response-content-encoding",
	"website",
}

func (s3 *S3) payload(method, path string, q url.Values, h http.Header, expires time.Time) string {
	items := make([]string, 4, 10)
	items[0] = method
	items[1] = h.Get("Content-Md5")
	items[2] = h.Get("Content-Type")
	if !expires.IsZero() {
		items[3] = strconv.FormatInt(expires.Unix(), 10)
	} else {
		items[3] = h.Get("Date")
	}
	xamz := make([]string, 0, len(h))
	for k, v := range h {
		if !strings.HasPrefix(k, "X-Amz") {
			continue
		}
		if k == "X-Amz-Date" {
			items[3] = ""
		}
		xamz = append(xamz, k+":"+strings.Join(v, ","))
	}
	if len(xamz) > 0 {
		sort.StringSlice(xamz).Sort()
		items = append(items, xamz...)
		xamz = nil
	}
	var rawQuery string
	if len(q) > 0 {
		values := make([]string, 0, 6)
		for k, vv := range q {
			var found bool
			for _, qk := range querySign {
				if k == qk {
					found = true
					break
				}
			}
			if !found {
				continue
			}
			for _, v := range vv {
				values = append(values, k+"="+v)
			}
		}
		if len(values) > 0 {
			sort.StringSlice(values).Sort()
			rawQuery = strings.Join(values, "&")
		}
	}
	canonicalURL := url.URL{
		Path:     path,
		RawQuery: rawQuery,
	}
	items = append(items, canonicalURL.RequestURI())
	return strings.Join(items, "\n")
}

func (s3 *S3) sign(str string) string {
	hash := hmac.New(sha1.New, []byte(s3.SecretKey))
	hash.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
