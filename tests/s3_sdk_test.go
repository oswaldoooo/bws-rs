package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3Sdk(t *testing.T) {
	var (
		host      = "127.0.0.1"
		port      = 9900
		accesskey = "root"
		secretkey = "root12345"
		region    = "us-east-1"
	)

	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service == s3.ServiceID {
			return aws.Endpoint{
				URL:           fmt.Sprintf("http://%s:%d", host, port),
				SigningRegion: "us-east-1",
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	// 加载 AWS 配置，指定自定义端点解析器
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accesskey, secretkey, "")),
	)
	if err != nil {
		log.Fatalf("无法加载 AWS 配置: %v", err)
	}
	// 创建 S3 客户端
	cli := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
	var (
		bucket = "itest"
		key    = "test.txt"
	)
	fd, err := os.OpenFile("./test.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	out, err := cli.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatal(err)
	}
	var upNo int32 = 1

	resp, err := cli.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: &bucket, Key: &key, PartNumber: &upNo, UploadId: out.UploadId, Body: fd,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket: &bucket, Key: &key, UploadId: out.UploadId, MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					ETag: resp.ETag, PartNumber: &upNo,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
