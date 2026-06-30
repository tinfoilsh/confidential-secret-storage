package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	tenant  string
	http    *http.Client
}

func NewBucketsClient(baseURL, tenant string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		tenant:  tenant,
		http:    &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) Put(ctx context.Context, key string, plaintext, encKey []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.objectURL(key), bytes.NewReader(plaintext))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(plaintext))
	c.setHeaders(req, encKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("buckets put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	code, msg := s3Error(resp.Body)
	return fmt.Errorf("buckets: status %d: %s", resp.StatusCode, joinCodeMessage(code, msg))
}

func (c *Client) objectURL(key string) string {
	return c.baseURL + "/bucket/" + key
}

func (c *Client) setHeaders(req *http.Request, encKey []byte) {
	req.Header.Set("X-Tinfoil-Tenant-Id", c.tenant)
	req.Header.Set("X-Tinfoil-Encryption-Key", base64.StdEncoding.EncodeToString(encKey))
}

type s3ErrorBody struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func s3Error(r io.Reader) (code, message string) {
	raw, _ := io.ReadAll(io.LimitReader(r, 8192))
	var e s3ErrorBody
	if err := xml.Unmarshal(raw, &e); err == nil && e.Code != "" {
		return e.Code, e.Message
	}
	return "", strings.TrimSpace(string(raw))
}

func joinCodeMessage(code, message string) string {
	switch {
	case code != "" && message != "":
		return code + ": " + message
	case code != "":
		return code
	default:
		return message
	}
}
