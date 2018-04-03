package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jjeffery/errors"
)

const (
	lambdaName = "spaproxy"
)

var (
	initialDir  string
	artifactDir string
	workDir     string
	goCommand   = "go"
)

var (
	version string
	commit  string
	date    string
)

var option struct {
	allowDirty bool
}

func init() {
	flag.BoolVar(&option.allowDirty, "allow-dirty", false, "allow git modifications")
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	if !option.allowDirty {
		checkGitNotDirty()
	}

	version = os.Getenv("BUILD_NUMBER")
	if version == "" {
		log.Fatal("BUILD_NUMBER not set")
	}
	commit = getGitRevision()
	date = time.Now().Format(time.RFC3339)

	var err error

	// allows the go command to be overridden by environment variable,
	// eg "go1.9rc2"
	if s := os.Getenv("GO"); s != "" {
		goCommand = s
	}

	// directories
	if initialDir, err = os.Getwd(); err != nil {
		log.Fatal(err)
	}
	artifactDir = filepath.Join(initialDir, "artifacts")
	workDir = filepath.Join(initialDir, fmt.Sprintf("build-work-dir-%d", os.Getpid()))

	for _, dir := range []string{artifactDir, workDir} {
		mkdir(dir)
	}

	if err = compile("linux", "amd64"); err != nil {
		log.Fatal(err)
	}

	buildZipFile()

	if err = os.RemoveAll(workDir); err != nil {
		log.Fatalf("cannot remove work dir %s: %v", workDir, err)
	}
}

func checkGitNotDirty() {
	if err := isGitDirty(); err != nil {
		log.Fatalf("uncommitted changes in git respository: %v", err)
	}
}

func isGitDirty() error {
	cmd := exec.Cmd{
		Path:   findExe("git"),
		Args:   []string{"git", "diff", "--quiet"},
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func getGitRevision() string {
	var suffix string
	if err := isGitDirty(); err != nil {
		suffix = "-dirty"
	}
	buf := bytes.Buffer{}
	cmd := exec.Cmd{
		Path:   findExe("git"),
		Args:   []string{"git", "rev-parse", "--short=12", "HEAD"},
		Stdout: &buf,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
	}

	if err := cmd.Run(); err != nil {
		log.Fatalf("cannot run git: %v", err)
	}

	return strings.TrimSpace(string(buf.Bytes())) + suffix
}

func mkdir(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("cannot create dir %s: %v", dir, err)
	}
}

func compile(goos string, goarch string) error {
	errors := errors.With("GOOS", goos, "GOARCH", goarch)
	cmd := exec.Cmd{
		Path:   findExe(goCommand),
		Args:   []string{goCommand, "build", "-a", "-o", filepath.Join(workDir, lambdaName)},
		Env:    buildEnv(goos, goarch),
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
	}

	ldflags := fmt.Sprintf("-s -w -X main.version=%s -X main.commit=%s -X main.date=%s", version, commit, date)

	cmd.Args = append(cmd.Args, "-ldflags")
	cmd.Args = append(cmd.Args, ldflags)
	cmd.Args = append(cmd.Args, ".")

	log.Print(strings.Join(cmd.Args, " "))

	err := cmd.Run()
	if err != nil {
		return errors.Wrap(err, "cannot build")
	}
	return nil
}

func findExe(name string) string {
	exe, err := exec.LookPath(name)
	if err != nil {
		log.Fatalf("cannot find executable %s: %v", name, err)
	}
	return exe
}

func buildEnv(goos string, goarch string) []string {
	var env []string

	getenv := func(name string) string {
		v := os.Getenv(name)
		return name + "=" + v
	}

	if runtime.GOOS == "windows" {
		env = append(env, getenv("TEMP"))
	}
	env = append(env, getenv("PATH"))
	env = append(env, getenv("GOPATH"))
	env = append(env, "GOOS="+goos)
	env = append(env, "GOARCH="+goarch)
	return env
}

func buildZipFile() {
	zipFileName := filepath.Join(artifactDir, fmt.Sprintf("%s-%s.zip", lambdaName, version))
	file, err := os.Create(zipFileName)
	if err != nil {
		log.Fatalf("cannot create file %s: %v", zipFileName, err)
	}
	defer func() { file.Close() }()

	zipFile := zip.NewWriter(file)
	defer func() { zipFile.Close() }()

	doDirectory(zipFile, workDir, "")
}

func doDirectory(zipFile *zip.Writer, dir string, base string) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("cannot read directory %s: %v", dir, err)
	}

	for _, f := range files {
		var filename string
		if base == "" {
			filename = f.Name()
		} else {
			// use path.Join because we must have forward slashes
			filename = path.Join(base, f.Name())
		}
		if f.IsDir() {
			doDirectory(zipFile, filepath.Join(dir, f.Name()), filename)
		} else {
			filePath := filepath.Join(dir, f.Name())

			var filemode os.FileMode
			if f.IsDir() {
				filemode = 0755 | os.ModeDir
			} else if filepath.Base(dir) == "bin" || path.Ext(filename) == "" {
				filemode = 0755
			} else {
				filemode = 0644
			}

			fileHeader := &zip.FileHeader{
				Name:   filename,
				Method: zip.Deflate,
			}
			fileHeader.SetMode(filemode)
			fileHeader.SetModTime(f.ModTime())
			writeOneFile(zipFile, fileHeader, filePath)
		}
	}
}

func writeOneFile(zipFile *zip.Writer, header *zip.FileHeader, filePath string) {
	log.Printf("zip file file=%s", filePath)
	writer, err := zipFile.CreateHeader(header)
	if err != nil {
		log.Fatalf("cannot create zip file entry %s: %v", header.Name, err)
	}

	reader, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("cannot open file %s: %v", filePath, err)
	}
	defer func() { reader.Close() }()

	_, err = io.Copy(writer, reader)
	if err != nil {
		log.Fatalf("cannot copy file %s: %v", filePath, err)
	}
}
