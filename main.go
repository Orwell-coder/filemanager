package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	IsDir   bool      `json:"is_dir"`
	Md5Sum  string    `json:"ms5sum"`
}

type FileSystem struct {
	RootDir      string
	FileMap      map[string][]FileInfo
	mutex        sync.RWMutex
	ScanInterval time.Duration
}

func NewFileSystem(rootDir string, scanInterval time.Duration) *FileSystem {
	return &FileSystem{
		RootDir:      rootDir,
		FileMap:      make(map[string][]FileInfo),
		ScanInterval: scanInterval,
	}
}

// calculateMD5 计算文件的 MD5 校验和
func MD5Sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := md5.New()
	buf := make([]byte, 4096)

	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return "", err
		}
		if n == 0 {
			break
		}
		h.Write(buf[:n])
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func cpuInfo() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	return string(data)
}

func cpuUsage() string {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return ""
	}
	return string(data)
}

func memInfo() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return ""
	}
	return string(data)
}

func memUsage() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return ""
	}
	return string(data)
}

func diskInfo() string {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return ""
	}
	return string(data)
}

func diskUsage() string {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return ""
	}
	return string(data)
}

func (fs *FileSystem) Start() {
	go fs.periodicScan()
}

func (fs *FileSystem) periodicScan() {
	for {
		fs.ScanDirectory(fs.RootDir)
		fs.SaveToDisk()
		time.Sleep(fs.ScanInterval)
	}
}

func (fs *FileSystem) ScanDirectory(dir string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Printf("Error reading directory %s: %v\n", dir, err)
		return
	}

	var fileInfos []FileInfo
	for _, file := range files {
		fileInfo := FileInfo{
			Name:    file.Name(),
			Size:    file.Size(),
			ModTime: file.ModTime(),
			IsDir:   file.IsDir(),
			Md5Sum:  "",
		}
		fileInfos = append(fileInfos, fileInfo)

		if file.IsDir() {
			fs.ScanDirectory(filepath.Join(dir, file.Name()))
		}
	}

	fs.mutex.Lock()
	fs.FileMap[dir] = fileInfos
	fs.mutex.Unlock()
}

func (fs *FileSystem) SaveToDisk() {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	data, err := json.MarshalIndent(fs.FileMap, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling file map: %v\n", err)
		return
	}

	err = os.WriteFile("file_map.json", data, 0644)
	if err != nil {
		fmt.Printf("Error writing file map to disk: %v\n", err)
	}
}

func (fs *FileSystem) LoadFromDisk() {
	data, err := os.ReadFile("file_map.json")
	if err != nil {
		fmt.Printf("Error reading file map from disk: %v\n", err)
		return
	}

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	err = json.Unmarshal(data, &fs.FileMap)
	if err != nil {
		fmt.Printf("Error unmarshaling file map: %v\n", err)
	}
}

func (fs *FileSystem) ListDirectory(dir string, sortBy string, ascending bool) []FileInfo {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	files, ok := fs.FileMap[dir]
	if !ok {
		return nil
	}

	sort.Slice(files, func(i, j int) bool {
		// 目录 最前
		if files[i].IsDir && !files[j].IsDir {
			return true
		}
		if !files[i].IsDir && files[j].IsDir {
			return false
		}

		var less bool
		switch sortBy {
		case "name":
			less = files[i].Name < files[j].Name
		case "time":
			less = files[i].ModTime.Before(files[j].ModTime)
		case "size":
			less = files[i].Size < files[j].Size
		default:
			less = files[i].Name < files[j].Name
		}

		if !ascending {
			return !less
		}
		return less
	})

	// sort.Slice(files, func(i, j int) bool {
	// 	if files[i].IsDir && !files[j].IsDir {
	// 		return true
	// 	}
	// 	if !files[i].IsDir && files[j].IsDir {
	// 		return false
	// 	}
	// 	return files[i].ModTime.Before(files[j].ModTime)
	// })

	return files
}

type WebServer struct {
	FS *FileSystem
}

func NewWebServer(fs *FileSystem) *WebServer {
	return &WebServer{FS: fs}
}

func (ws *WebServer) HandleListDirectory(w http.ResponseWriter, r *http.Request) {
	currentDir := r.URL.Query().Get("dir")
	var dir string
	if currentDir == "" {
		dir = ws.FS.RootDir
	} else {
		dir = filepath.Join(ws.FS.RootDir, currentDir)
	}
	sortBy := r.URL.Query().Get("sort")
	ascending := r.URL.Query().Get("order") != "desc"

	files := ws.FS.ListDirectory(dir, sortBy, ascending)

	var parentDir string
	if dir == ws.FS.RootDir {
		parentDir = currentDir
	} else {
		parentDir = strings.ReplaceAll(filepath.Dir(dir), ws.FS.RootDir, "")
		parentDir = strings.TrimPrefix(parentDir, "/")
	}
	response := struct {
		CurrentDir string     `json:"current_dir"`
		ParentDir  string     `json:"parent_dir"`
		Files      []FileInfo `json:"files"`
	}{
		CurrentDir: currentDir,
		ParentDir:  parentDir,
		Files:      files,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) HandleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// 新增：处理文件上传
func (ws *WebServer) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dir := r.FormValue("dir")
	if dir == "" {
		dir = ws.FS.RootDir
	} else {
		dir = filepath.Join(ws.FS.RootDir, dir)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 创建目标文件
	dst, err := os.Create(filepath.Join(dir, header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// 复制文件内容
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 触发文件系统扫描
	ws.FS.ScanDirectory(dir)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "File uploaded successfully")
}

// 新增：处理文件下载
func (ws *WebServer) HandleDownload(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}

	fullPath := filepath.Join(ws.FS.RootDir, filePath)
	// fullPath := filePath
	// fmt.Println("fullPath: ", fullPath)
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(fullPath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if filestat, err := file.Stat(); err == nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", filestat.Size()))
	}
	// w.Header().Set("Content-Length", fmt.Sprintf("%d", file.Stat().Size()))

	// 发送文件内容
	io.Copy(w, file)
}

func (ws *WebServer) HandleMd5sum(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}

	if ms5sum, err := MD5Sum(filepath.Join(ws.FS.RootDir, file)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		response := struct {
			Md5Sum string `json:"md5sum"`
		}{Md5Sum: ms5sum}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

}

func (ws *WebServer) HandleResourceInfo(w http.ResponseWriter, r *http.Request) {

	response := struct {
		Disk struct {
			Total int `json:"total"`
			Free  int `json:"free"`
			Used  int `json:"used"`
		} `json:"disk"`
		Mem struct {
			Total int `json:"total"`
			Free  int `json:"free"`
			Used  int `json:"used"`
		} `json:"mem"`
		Cpu struct {
			Product     string `json:"product"`
			Vendor      string `json:"vendor"`
			PhysicalNum string `json:"physical_num"`
			CoreNum     string `json:"core_num"`
			Total       int    `json:"total"`
			Free        int    `json:"free"`
			Used        int    `json:"used"`
		} `json:"cpu"`
	}{}

	cpu.Info()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

// 新增：处理文件搜索
func (ws *WebServer) HandleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Search query is required", http.StatusBadRequest)
		return
	}

	response := struct {
		CurrentDir string     `json:"current_dir"`
		ParentDir  string     `json:"parent_dir"`
		Files      []FileInfo `json:"files"`
	}{
		CurrentDir: "",
		ParentDir:  "",
		Files:      []FileInfo{},
	}

	// 在文件映射中搜索
	ws.FS.mutex.RLock()
	defer ws.FS.mutex.RUnlock()

	for dir, files := range ws.FS.FileMap {
		for _, file := range files {
			if strings.Contains(strings.ToLower(file.Name), strings.ToLower(query)) {
				file.Name = strings.ReplaceAll(filepath.Join(dir, file.Name), ws.FS.RootDir, "")
				file.Name = strings.TrimPrefix(file.Name, "/")
				response.Files = append(response.Files, file)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func runAsDaemon() {
	if os.Getppid() != 1 {
		args := append([]string{os.Args[0]}, os.Args[1:]...)
		os.StartProcess(os.Args[0], args, &os.ProcAttr{Dir: "", Env: nil, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
		os.Exit(0)
	}
}

func globalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] [%s] %s\n", r.RemoteAddr, r.UserAgent(), r.URL.Path)
		// log.Printf("Global Middleware triggered for:%v\n", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func router(fs *FileSystem) http.Handler {
	ws := NewWebServer(fs)

	mux := http.NewServeMux()

	mux.HandleFunc("/", ws.HandleIndex)
	mux.HandleFunc("/list", ws.HandleListDirectory)
	mux.HandleFunc("/upload", ws.HandleUpload)
	mux.HandleFunc("/download", ws.HandleDownload)
	mux.HandleFunc("/search", ws.HandleSearch)
	mux.HandleFunc("/md5", ws.HandleMd5sum)
	mux.HandleFunc("/resource_info", ws.HandleResourceInfo)

	return globalMiddleware(mux)
}

func main() {
	// set log file
	logFile, err := os.OpenFile("/var/log/fileserver.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening log file: %v\n", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// current directory
	currRir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Error get current directory: %v\n", err)
	}

	daemon := flag.Bool("d", false, "run as a daemon")
	dir := flag.String("dir", currRir, "directory to scan")
	flag.Parse()

	if *daemon {
		runAsDaemon()
	}

	// 创建一个channel来接收信号
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// fs := NewFileSystem("/home/samba/tvm", 5*time.Minute)
	fs := NewFileSystem(*dir, 5*time.Minute)
	fs.LoadFromDisk()
	fs.Start()

	httpHandler := router(fs)
	// fmt.Println(*dir)

	go func() {
		log.Println("Server is running on http://0.0.0.0:8080")
		if err := http.ListenAndServe("0.0.0.0:8080", httpHandler); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// 等待信号
	<-sigs
	log.Println("Shutting down...")
}
