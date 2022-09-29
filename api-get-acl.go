/*
 * MinIO Go Library for Amazon S3 Compatible Cloud Storage
 * Copyright 2018 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package minio

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"io"
)

type GranteeDecode struct {
	XMLNS       string `xml:"xsi,attr" json:"xmlns"`
	XMLXSI      string `xml:"type,attr" json:"xmlxsi"`
	Type        string `xml:"Type" json:"type"`
	ID          string `xml:"ID,omitempty" json:"id,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty" json:"displayName,omitempty"`
	URI         string `xml:"URI,omitempty" json:"uri,omitempty"`
	Email       string `xlm:"EmailAddress,omitempty" json:"email,omitempty"`
}

type GrantDecode struct {
	Grantee    GranteeDecode `xml:"Grantee" json:"Grantee"`
	Permission string        `xml:"Permission" json:"Permission"`
}

type AccessControlPolicyDecode struct {
	XMLName           xml.Name `xml:"AccessControlPolicy" json:"AccessControlPolicy"`
	Owner             Owner    `xml:"Owner" json:"Owner"`
	AccessControlList struct {
		Grants []GrantDecode `xml:"Grant" json:"Grant"`
	} `xml:"AccessControlList" json:"AccessControlList"`
}

// GetObjectACL get object ACLs
func (c *Client) GetObjectACL(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error) {
	resp, err := c.executeMethod(ctx, http.MethodGet, requestMetadata{
		bucketName: bucketName,
		objectName: objectName,
		queryValues: url.Values{
			"acl": []string{""},
		},
	})
	if err != nil {
		return nil, err
	}
	defer closeResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, httpRespToErrorResponse(resp, bucketName, objectName)
	}

	res := &AccessControlPolicyDecode{}

	if err := xmlDecoder(resp.Body, res); err != nil {
		return nil, err
	}

	objInfo, err := c.StatObject(ctx, bucketName, objectName, StatObjectOptions{})
	if err != nil {
		return nil, err
	}

	objInfo.Owner.DisplayName = res.Owner.DisplayName
	objInfo.Owner.ID = res.Owner.ID

	objInfo.Grant = append(objInfo.Grant, res.AccessControlList.Grants...)

	cannedACL := getCannedACL(res)
	if cannedACL != "" {
		objInfo.Metadata.Add("X-Amz-Acl", cannedACL)
		return &objInfo, nil
	}

	grantACL := getAmzGrantACL(res)
	for k, v := range grantACL {
		objInfo.Metadata[k] = v
	}

	return &objInfo, nil
}

func getCannedACL(aCPolicy *AccessControlPolicyDecode) string {
	grants := aCPolicy.AccessControlList.Grants

	switch {
	case len(grants) == 1:
		if grants[0].Grantee.URI == "" && grants[0].Permission == "FULL_CONTROL" {
			return "private"
		}
	case len(grants) == 2:
		for _, g := range grants {
			if g.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" && g.Permission == "READ" {
				return "authenticated-read"
			}
			if g.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" && g.Permission == "READ" {
				return "public-read"
			}
			if g.Permission == "READ" && g.Grantee.ID == aCPolicy.Owner.ID {
				return "bucket-owner-read"
			}
		}
	case len(grants) == 3:
		for _, g := range grants {
			if g.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" && g.Permission == "WRITE" {
				return "public-read-write"
			}
		}
	}
	return ""
}

func getAmzGrantACL(aCPolicy *AccessControlPolicyDecode) map[string][]string {
	grants := aCPolicy.AccessControlList.Grants
	res := map[string][]string{}

	for _, g := range grants {
		switch {
		case g.Permission == "READ":
			res["X-Amz-Grant-Read"] = append(res["X-Amz-Grant-Read"], "id="+g.Grantee.ID)
		case g.Permission == "WRITE":
			res["X-Amz-Grant-Write"] = append(res["X-Amz-Grant-Write"], "id="+g.Grantee.ID)
		case g.Permission == "READ_ACP":
			res["X-Amz-Grant-Read-Acp"] = append(res["X-Amz-Grant-Read-Acp"], "id="+g.Grantee.ID)
		case g.Permission == "WRITE_ACP":
			res["X-Amz-Grant-Write-Acp"] = append(res["X-Amz-Grant-Write-Acp"], "id="+g.Grantee.ID)
		case g.Permission == "FULL_CONTROL":
			res["X-Amz-Grant-Full-Control"] = append(res["X-Amz-Grant-Full-Control"], "id="+g.Grantee.ID)
		}
	}
	return res
}

func (c *Client) GetObjectACLstring(ctx context.Context, bucketName, objectName string) (string, error) {
	resp, err := c.executeMethod(ctx, http.MethodGet, requestMetadata{
		bucketName: bucketName,
		objectName: objectName,
		queryValues: url.Values{
			"acl": []string{""},
		},
	})
	if err != nil {
		return "", err
	}
	defer closeResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return "", httpRespToErrorResponse(resp, bucketName, objectName)
	}
	aclBytes, _ := io.ReadAll(resp.Body)
	return string(aclBytes), nil
}

func (c *Client) GetBucketACLstring(ctx context.Context, bucketName string)(string, error) {
	resp, err := c.executeMethod(ctx, http.MethodGet, requestMetadata{
		bucketName: bucketName,
		queryValues: url.Values{
			"acl": []string{""},
		},
	})
	if err != nil {
		return "", err
	}
	defer closeResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return "", httpRespToErrorResponse(resp, bucketName, "")
	}

	aclBytes, _ := io.ReadAll(resp.Body)

	return string(aclBytes), nil
}
