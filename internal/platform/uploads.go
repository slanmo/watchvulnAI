package platform

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/gin-gonic/gin"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

var logoName = regexp.MustCompile(`^[a-f0-9]{64}\.(png|jpg|gif)$`)

func (s *Server) uploadLogo(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20+65536)
	file, err := c.FormFile("file")
	if err != nil {
		fail(c, 400, "请选择2MB以内PNG、JPEG或GIF图片")
		return
	}
	if c.Request.MultipartForm != nil {
		defer c.Request.MultipartForm.RemoveAll()
	}
	f, err := file.Open()
	if err != nil {
		fail(c, 400, err)
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		fail(c, 400, "图片不能超过2MB")
		return
	}
	cfg, kind, err := image.DecodeConfig(bytes.NewReader(raw))
	ext := map[string]string{"png": "png", "jpeg": "jpg", "gif": "gif"}[kind]
	if err != nil || ext == "" || cfg.Width > 4096 || cfg.Height > 4096 || cfg.Width < 1 || cfg.Height < 1 {
		fail(c, 400, "请上传尺寸不超过4096×4096的PNG、JPEG或GIF图片")
		return
	}
	name := fmt.Sprintf("%x.%s", sha256.Sum256(raw), ext)
	dir := filepath.Join(s.dir, "logos")
	if err = os.MkdirAll(dir, 0700); err == nil {
		err = os.WriteFile(filepath.Join(dir, name), raw, 0600)
	}
	if err != nil {
		fail(c, 500, "保存图片失败")
		return
	}
	c.JSON(201, gin.H{"url": "/api/logos/" + name})
}
func (s *Server) serveLogo(c *gin.Context) {
	name := c.Param("name")
	if !logoName.MatchString(name) {
		fail(c, 404, "图片不存在")
		return
	}
	path := filepath.Join(s.dir, "logos", name)
	if _, err := os.Stat(path); err != nil {
		fail(c, 404, "图片不存在")
		return
	}
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.File(path)
}
