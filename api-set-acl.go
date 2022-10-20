package minio

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
)

type GranteeEncode struct {
	XMLNS       string `xml:"xmlns:xsi,attr" json:"xmlns"`
	XMLXSI      string `xml:"xsi:type,attr" json:"xmlxsi"`
	Type        string `xml:"Type" json:"type"`
	ID          string `xml:"ID,omitempty" json:"id,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty" json:"displayName,omitempty"`
	URI         string `xml:"URI,omitempty" json:"uri,omitempty"`
	Email       string `xlm:"EmailAddress,omitempty" json:"email,omitempty"`
}

type GrantEncode struct {
	Grantee    GranteeEncode `xml:"Grantee" json:"Grantee"`
	Permission string        `xml:"Permission" json:"Permission"`
}

type AccessControlList struct {
	Grants []GrantEncode `xml:"Grant" json:"Grant"`
}

type AccessControlPolicyEncode struct {
	XMLName           xml.Name `xml:"AccessControlPolicy" json:"AccessControlPolicy"`
	Owner             Owner    `xml:"Owner" json:"Owner"`
	AccessControlList struct {
		Grants []GrantEncode `xml:"Grant" json:"Grant"`
	} `xml:"AccessControlList" json:"AccessControlList"`
}

func (c *Client) PutObjectAcl(ctx context.Context, bucketName, objectName string, acle *AccessControlPolicyEncode) error {
	aclstring, err := xml.Marshal(acle)
	if err != nil {
		return err
	}
	return c.PutObjectACLstring(ctx, bucketName, objectName, string(aclstring))
}

// GetObjectACL get object ACLs
func (c *Client) PutObjectACLstring(ctx context.Context, bucketName, objectName, acl string) error {
	resp, err := c.executeMethod(ctx, http.MethodPut, requestMetadata{
		bucketName: bucketName,
		objectName: objectName,
		queryValues: url.Values{
			"acl": []string{""},
		},
		contentBody:   strings.NewReader(acl),
		contentLength: int64(len(acl)),
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return httpRespToErrorResponse(resp, bucketName, objectName)
	}

	return nil
}

func (c *Client) PutBucketAcl(ctx context.Context, bucketName string, acle *AccessControlPolicyEncode) error {
	aclstring, err := xml.Marshal(acle)
	if err != nil {
		return err
	}

	return c.PutBucketACLstring(ctx, bucketName, string(aclstring))
}

func (c *Client) PutBucketACLstring(ctx context.Context, bucketName, acl string) error {
	resp, err := c.executeMethod(ctx, http.MethodPut, requestMetadata{
		bucketName: bucketName,
		queryValues: url.Values{
			"acl": []string{""},
		},
		contentBody:   strings.NewReader(acl),
		contentLength: int64(len(acl)),
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return httpRespToErrorResponse(resp, bucketName, "")
	}

	return nil
}
