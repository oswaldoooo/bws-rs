package tests

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestCreateBucket(t *testing.T) {
	creds, err := minio.New("127.0.0.1:9900", &minio.Options{
		Secure: false, Creds: credentials.NewStaticV4("root", "root12345", ""),
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = creds.BucketExists(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	err = creds.MakeBucket(context.Background(), "itest", minio.MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bkts, err := creds.ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(bkts)
	err = creds.RemoveBucket(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	err = creds.RemoveObject(context.Background(), "test", "test", minio.RemoveObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile("test.txt", []byte("hello"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := os.OpenFile("test.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	_, err = creds.PutObject(context.Background(), "test", "hello/world", fd, 5, minio.PutObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := creds.GetObject(context.Background(), "test", "test", minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Fatal("expect hello got [" + string(content) + "]")
	}
}
