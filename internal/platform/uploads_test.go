package platform

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogoUploadValidation(t *testing.T) {
	s := testServer(t)
	r := gin.New()
	r.POST("/upload", s.uploadLogo)
	r.GET("/api/logos/:name", s.serveLogo)
	upload := func(raw []byte) *httptest.ResponseRecorder {
		var b bytes.Buffer
		writer := multipart.NewWriter(&b)
		f, err := writer.CreateFormFile("file", "logo.png")
		if err != nil {
			t.Fatal(err)
		}
		f.Write(raw)
		writer.Close()
		req := httptest.NewRequest("POST", "/upload", &b)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	if w := upload([]byte("<svg onload=alert(1)>")); w.Code != 400 {
		t.Fatal(w.Code)
	}
	var imageData bytes.Buffer
	png.Encode(&imageData, image.NewRGBA(image.Rect(0, 0, 16, 16)))
	w := upload(imageData.Bytes())
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var response struct {
		URL string `json:"url"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)
	req := httptest.NewRequest(http.MethodGet, response.URL, nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), imageData.Bytes()) {
		t.Fatal("uploaded image not served")
	}
}
func TestNotificationCards(t *testing.T) {
	f, d := notificationCards("测试标题", strings.Repeat("情报摘要", 1000), "https://example.com", nil)
	if f["header"] == nil || d["msgtype"] != "actionCard" {
		t.Fatal(f, d)
	}
	action := d["actionCard"].(map[string]string)
	if action["singleURL"] != "https://example.com" || len([]rune(action["text"])) > 1500 {
		t.Fatal(action)
	}
}
