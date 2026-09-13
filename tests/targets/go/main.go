package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	uploadsDir  = "./plugins"
	managePORT  = "9090"
	webshellBin = "./plugins/webshell"
)

var (
	mu         sync.Mutex
	childProc  *exec.Cmd
)

func listFiles() string {
	var sb strings.Builder
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		sb.WriteString(fmt.Sprintf(`<li><a href="/plugins/%s">%s</a> (%d bytes)</li>`, e.Name(), e.Name(), size))
	}
	return sb.String()
}

func page(msg string) string {
	msgHtml := ""
	if msg != "" {
		msgHtml = `<div class="msg">` + msg + `</div>`
	}
	return `<!DOCTYPE html>
<html><head><title>Go Application Server</title>
<style>
body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:0 20px}
h1{font-size:1.4em}
form{margin:20px 0;padding:16px;border:1px solid #ccc;border-radius:4px;background:#f9f9f9}
input[type=file]{margin-right:8px}
.msg{padding:8px 12px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:4px;margin-bottom:12px}
ul{list-style:none;padding:0} li{padding:4px 0}
</style></head><body>
<h1>Go Application Server</h1>
` + msgHtml + `
<form method="post" enctype="multipart/form-data" action="/upload">
    <input type="file" name="file" required>
    <button type="submit">Upload</button>
</form>
<h3>Uploads</h3><ul>` + listFiles() + `</ul>
</body></html>`
}

func stopChild() {
	mu.Lock()
	defer mu.Unlock()
	if childProc != nil && childProc.Process != nil {
		childProc.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- childProc.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			childProc.Process.Kill()
			<-done
		}
		childProc = nil
	}
}

func compileAndRun(goFile string) (string, error) {
	stopChild()

	cmd := exec.Command("go", "build", "-o", webshellBin, goFile)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("compile failed: %s\n%s", err, string(out))
	}

	mu.Lock()
	childProc = exec.Command(webshellBin)
	childProc.Stdout = os.Stdout
	childProc.Stderr = os.Stderr
	err = childProc.Start()
	mu.Unlock()

	if err != nil {
		return "", fmt.Errorf("start failed: %s", err)
	}

	return fmt.Sprintf("Compiled and started (PID %d)", childProc.Process.Pid), nil
}

func main() {
	os.MkdirAll(uploadsDir, 0755)

	mux := http.NewServeMux()

	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		contentType := r.Header.Get("Content-Type")

		if strings.HasPrefix(contentType, "multipart/form-data") {
			r.ParseMultipartForm(32 << 20)
			file, header, err := r.FormFile("file")
			if err != nil {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, page("Upload failed: "+err.Error()))
				return
			}
			defer file.Close()

			destPath := filepath.Join(uploadsDir, header.Filename)
			dst, err := os.Create(destPath)
			if err != nil {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, page("Failed to create file: "+err.Error()))
				return
			}
			defer dst.Close()
			io.Copy(dst, file)

			msg := fmt.Sprintf(`Uploaded: <a href="/plugins/%s">%s</a>`, header.Filename, header.Filename)

			if strings.HasSuffix(header.Filename, ".go") {
				result, err := compileAndRun(destPath)
				if err != nil {
					msg += fmt.Sprintf("<br>Compile/run error: %s", err.Error())
				} else {
					msg += fmt.Sprintf("<br>%s", result)
				}
			}

			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(msg))
		} else {
			filename := r.URL.Query().Get("filename")
			if filename == "" {
				http.Error(w, "filename query param required", 400)
				return
			}
			destPath := filepath.Join(uploadsDir, filename)
			dst, err := os.Create(destPath)
			if err != nil {
				http.Error(w, "Failed to create file: "+err.Error(), 500)
				return
			}
			io.Copy(dst, r.Body)
			dst.Close()

			if strings.HasSuffix(filename, ".go") {
				result, err := compileAndRun(destPath)
				if err != nil {
					fmt.Fprintf(w, "Uploaded but compile/run failed: %s", err.Error())
					return
				}
				fmt.Fprintf(w, "Uploaded and started: %s", result)
			} else {
				fmt.Fprintf(w, "Uploaded: %s", filename)
			}
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(""))
			return
		}

		filePath := filepath.Join(".", r.URL.Path)
		if _, err := os.Stat(filePath); err == nil {
			http.ServeFile(w, r, filePath)
			return
		}

		http.NotFound(w, r)
	})

	fmt.Printf("Go target management server on :%s, webshell will run on :8080\n", managePORT)
	http.ListenAndServe(":"+managePORT, mux)
}
