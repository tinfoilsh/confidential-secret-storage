package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("buckets: put status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) objectURL(key string) string {
	return c.baseURL + "/bucket/" + key
}

func (c *Client) setHeaders(req *http.Request, encKey []byte) {
	req.Header.Set("X-Tinfoil-Tenant-Id", c.tenant)
	req.Header.Set("X-Tinfoil-Encryption-Key", base64.StdEncoding.EncodeToString(encKey))
}
