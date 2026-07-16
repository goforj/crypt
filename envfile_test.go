package crypt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// staticEntropy returns one deterministic key or a configured failure.
type staticEntropy struct {
	key string
	err error
}

// countingEntropy proves invalid existing keys fail before fresh entropy is consumed.
type countingEntropy struct {
	key   string
	calls int
}

// Generate counts calls before returning its configured key.
func (entropy *countingEntropy) Generate() (string, error) {
	entropy.calls++
	return entropy.key, nil
}

// Generate implements entropySource without touching process-global randomness.
func (entropy staticEntropy) Generate() (string, error) {
	return entropy.key, entropy.err
}

// faultFileSystem injects atomic-write failures while delegating all normal behavior.
type faultFileSystem struct {
	envFileSystem
	lstatError  error
	readError   error
	createError error
	renameError error
	removeError error
	openError   error
	temporary   func(envTemporaryFile) envTemporaryFile
	directory   func(envSyncFile) envSyncFile
}

// Lstat returns an injected inspection failure or delegates to the wrapped filesystem.
func (fileSystem faultFileSystem) Lstat(name string) (os.FileInfo, error) {
	if fileSystem.lstatError != nil {
		return nil, fileSystem.lstatError
	}
	return fileSystem.envFileSystem.Lstat(name)
}

// ReadFile returns an injected read failure or delegates to the wrapped filesystem.
func (fileSystem faultFileSystem) ReadFile(name string) ([]byte, error) {
	if fileSystem.readError != nil {
		return nil, fileSystem.readError
	}
	return fileSystem.envFileSystem.ReadFile(name)
}

// CreateTemp returns an injected error or wraps the real same-directory temporary file.
func (fileSystem faultFileSystem) CreateTemp(dir, pattern string) (envTemporaryFile, error) {
	if fileSystem.createError != nil {
		return nil, fileSystem.createError
	}
	temporary, err := fileSystem.envFileSystem.CreateTemp(dir, pattern)
	if err != nil || fileSystem.temporary == nil {
		return temporary, err
	}
	return fileSystem.temporary(temporary), nil
}

// Rename returns an injected error before the temporary file can replace the target.
func (fileSystem faultFileSystem) Rename(oldPath, newPath string) error {
	if fileSystem.renameError != nil {
		return fileSystem.renameError
	}
	return fileSystem.envFileSystem.Rename(oldPath, newPath)
}

// Remove returns an injected cleanup error or removes the temporary file normally.
func (fileSystem faultFileSystem) Remove(name string) error {
	if fileSystem.removeError != nil {
		_ = fileSystem.envFileSystem.Remove(name)
		return fileSystem.removeError
	}
	return fileSystem.envFileSystem.Remove(name)
}

// Open returns an injected error or wraps the directory sync handle.
func (fileSystem faultFileSystem) Open(name string) (envSyncFile, error) {
	if fileSystem.openError != nil {
		return nil, fileSystem.openError
	}
	directory, err := fileSystem.envFileSystem.Open(name)
	if err != nil || fileSystem.directory == nil {
		return directory, err
	}
	return fileSystem.directory(directory), nil
}

// faultTemporaryFile injects one failure while still allowing deterministic cleanup.
type faultTemporaryFile struct {
	envTemporaryFile
	chmodError error
	writeError error
	syncError  error
	closeError error
}

// observingTemporaryFile records permissions at the moment secret bytes are written.
type observingTemporaryFile struct {
	envTemporaryFile
	modeDuringWrite os.FileMode
}

// Write verifies preparation keeps CreateTemp's private mode until content is complete.
func (file *observingTemporaryFile) Write(data []byte) (int, error) {
	info, err := os.Stat(file.Name())
	if err != nil {
		return 0, err
	}
	file.modeDuringWrite = info.Mode().Perm()
	return file.envTemporaryFile.Write(data)
}

// Chmod returns an injected permission failure before content is written.
func (file *faultTemporaryFile) Chmod(mode os.FileMode) error {
	if file.chmodError != nil {
		return file.chmodError
	}
	return file.envTemporaryFile.Chmod(mode)
}

// Write returns an injected write failure without partially accepting bytes.
func (file *faultTemporaryFile) Write(data []byte) (int, error) {
	if file.writeError != nil {
		return 0, file.writeError
	}
	return file.envTemporaryFile.Write(data)
}

// Sync returns an injected durability failure after content reaches the temporary file.
func (file *faultTemporaryFile) Sync() error {
	if file.syncError != nil {
		return file.syncError
	}
	return file.envTemporaryFile.Sync()
}

// Close closes the real descriptor before returning an injected close failure.
func (file *faultTemporaryFile) Close() error {
	err := file.envTemporaryFile.Close()
	if file.closeError != nil {
		return file.closeError
	}
	return err
}

// faultSyncFile injects directory durability and close failures after rename.
type faultSyncFile struct {
	envSyncFile
	syncError  error
	closeError error
}

// Sync returns an injected directory durability failure.
func (file *faultSyncFile) Sync() error {
	if file.syncError != nil {
		return file.syncError
	}
	return file.envSyncFile.Sync()
}

// Close closes the real directory before returning an injected close failure.
func (file *faultSyncFile) Close() error {
	err := file.envSyncFile.Close()
	if file.closeError != nil {
		return file.closeError
	}
	return err
}

// mutatingFileSystem simulates an unrelated in-place writer between snapshot and rename.
type mutatingFileSystem struct {
	envFileSystem
	path        string
	replacement []byte
	mutex       sync.Mutex
	lstatCalls  int
}

// Lstat mutates the target on the second inspection so conflict detection can reject it.
func (fileSystem *mutatingFileSystem) Lstat(name string) (os.FileInfo, error) {
	fileSystem.mutex.Lock()
	defer fileSystem.mutex.Unlock()
	fileSystem.lstatCalls++
	if fileSystem.lstatCalls == 2 {
		if err := os.WriteFile(fileSystem.path, fileSystem.replacement, 0o600); err != nil {
			return nil, err
		}
	}
	return fileSystem.envFileSystem.Lstat(name)
}

// zeroWriter exercises writeAll's zero-progress protection.
type zeroWriter struct{}

// Write reports no progress and no error, which writeAll must treat as a short write.
func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

// writeTestEnv creates a regular test env file with an explicit mode.
func writeTestEnv(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write env fixture: %v", err)
	}
	return path
}

// readTestEnv returns exact bytes so formatting preservation assertions stay visible.
func readTestEnv(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env fixture: %v", err)
	}
	return string(data)
}

// envTestKey returns a valid deterministic AES-256 application key.
func envTestKey(fill byte) string {
	return "base64:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

// assertNoEnvTemps verifies every pre-rename failure cleaned its same-directory artifact.
func assertNoEnvTemps(t *testing.T, envPath string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(envPath), "."+filepath.Base(envPath)+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

// TestGenerateKeyToEnvCreatesSecureFile guards secure defaults for newly created env files.
func TestGenerateKeyToEnvCreatesSecureFile(t *testing.T) {
	directory := t.TempDir()
	envPath := filepath.Join(directory, ".env")
	key, err := GenerateKeyToEnv(envPath)
	if err != nil {
		t.Fatalf("GenerateKeyToEnv: %v", err)
	}
	if got := readTestEnv(t, envPath); got != "APP_KEY="+key+"\n" {
		t.Fatalf("new env content = %q", got)
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat generated env: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new env mode = %o", info.Mode().Perm())
	}
	assertNoEnvTemps(t, envPath)
}

// TestGenerateKeyToEnvIsDestructiveButFormattingPreserving guards reset semantics without formatting drift.
func TestGenerateKeyToEnvIsDestructiveButFormattingPreserving(t *testing.T) {
	envPath := writeTestEnv(t,
		"# keep\r\nexport APP_KEY = \"old\" # primary\r\nFOO = 'bar'\r\n APP_PREVIOUS_KEYS = 'old-a' # history\r\n# APP_PREVIOUS_KEYS=example\r\nAPP_PREVIOUS_KEYS=old-b\r\n",
		0o640,
	)
	before, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat original: %v", err)
	}

	key, err := GenerateKeyToEnv(envPath)
	if err != nil {
		t.Fatalf("GenerateKeyToEnv: %v", err)
	}
	want := "# keep\r\nexport APP_KEY = \"" + key + "\" # primary\r\nFOO = 'bar'\r\n# APP_PREVIOUS_KEYS=example\r\n"
	if got := readTestEnv(t, envPath); got != want {
		t.Fatalf("reset env formatting\ngot:  %q\nwant: %q", got, want)
	}
	after, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat replacement: %v", err)
	}
	if after.Mode().Perm() != 0o640 {
		t.Fatalf("existing env mode = %o", after.Mode().Perm())
	}
	if os.SameFile(before, after) {
		t.Fatal("GenerateKeyToEnv did not install an atomic replacement")
	}
}

// TestRotateKeyInEnvPreservesFormattingAndCanonicalizesDuplicates guards rotation formatting and duplicate handling.
func TestRotateKeyInEnvPreservesFormattingAndCanonicalizesDuplicates(t *testing.T) {
	first := envTestKey(1)
	ignored := envTestKey(2)
	last := envTestKey(3)
	older := envTestKey(4)
	newKey := envTestKey(5)
	envPath := writeTestEnv(t,
		"# keep\r\nexport APP_KEY = \""+first+"\" # primary\r\nOTHER='x'\r\n APP_PREVIOUS_KEYS = '"+ignored+","+ignored+"' # history\r\nAPP_KEY="+last+"\r\n# APP_PREVIOUS_KEYS=example\r\nAPP_PREVIOUS_KEYS="+older+"\r\n",
		0o600,
	)
	gotKey, err := rotateKeyInEnv(osEnvFileSystem{}, envPath, staticEntropy{key: newKey})
	if err != nil {
		t.Fatalf("rotateKeyInEnv: %v", err)
	}
	if gotKey != newKey {
		t.Fatalf("rotateKeyInEnv key = %q", gotKey)
	}
	want := "# keep\r\nexport APP_KEY = \"" + newKey + "\" # primary\r\nOTHER='x'\r\n APP_PREVIOUS_KEYS = '" + last + "," + older + "' # history\r\n# APP_PREVIOUS_KEYS=example\r\n"
	if got := readTestEnv(t, envPath); got != want {
		t.Fatalf("rotated env formatting\ngot:  %q\nwant: %q", got, want)
	}
}

// TestRotateKeyInEnvPreservesMissingTrailingNewline guards existing end-of-file formatting.
func TestRotateKeyInEnvPreservesMissingTrailingNewline(t *testing.T) {
	oldKey := envTestKey(1)
	newKey := envTestKey(2)
	envPath := writeTestEnv(t, "APP_KEY="+oldKey+"\nFOO=bar", 0o600)
	_, err := rotateKeyInEnv(osEnvFileSystem{}, envPath, staticEntropy{key: newKey})
	if err != nil {
		t.Fatalf("rotateKeyInEnv: %v", err)
	}
	if got, want := readTestEnv(t, envPath), "APP_KEY="+newKey+"\nFOO=bar\nAPP_PREVIOUS_KEYS="+oldKey; got != want {
		t.Fatalf("rotated env = %q, want %q", got, want)
	}
}

// TestRotateKeyInEnvPreservesReadOnlyMode guards explicit existing permission modes during replacement.
func TestRotateKeyInEnvPreservesReadOnlyMode(t *testing.T) {
	envPath := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o400)
	if _, err := rotateKeyInEnv(osEnvFileSystem{}, envPath, staticEntropy{key: envTestKey(2)}); err != nil {
		t.Fatalf("rotateKeyInEnv read-only file: %v", err)
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat rotated env: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("rotated env mode = %o", info.Mode().Perm())
	}
}

// TestAtomicTemporaryStaysPrivateWhileWriting guards secret preparation against premature permission widening.
func TestAtomicTemporaryStaysPrivateWhileWriting(t *testing.T) {
	envPath := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o644)
	var observed *observingTemporaryFile
	fileSystem := faultFileSystem{
		envFileSystem: osEnvFileSystem{},
		temporary: func(file envTemporaryFile) envTemporaryFile {
			observed = &observingTemporaryFile{envTemporaryFile: file}
			return observed
		},
	}
	if _, err := rotateKeyInEnv(fileSystem, envPath, staticEntropy{key: envTestKey(2)}); err != nil {
		t.Fatalf("rotateKeyInEnv: %v", err)
	}
	if observed == nil {
		t.Fatal("temporary file was not observed")
	}
	if observed.modeDuringWrite != 0o600 {
		t.Fatalf("temporary mode while writing = %o", observed.modeDuringWrite)
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat rotated env: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("final env mode = %o", info.Mode().Perm())
	}
}

// TestConcurrentRotateKeyInEnvRetainsEveryKey guards same-path rotation against lost history.
func TestConcurrentRotateKeyInEnvRetainsEveryKey(t *testing.T) {
	initial, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey: %v", err)
	}
	envPath := writeTestEnv(t, "APP_KEY="+initial+"\n", 0o600)

	const rotations = 24
	keys := make(chan string, rotations)
	errorsSeen := make(chan error, rotations)
	var wait sync.WaitGroup
	for index := 0; index < rotations; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, err := RotateKeyInEnv(envPath)
			if err != nil {
				errorsSeen <- err
				return
			}
			keys <- key
		}()
	}
	wait.Wait()
	close(keys)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent rotation: %v", err)
	}

	current, previous, err := readEnvKeys(envPath)
	if err != nil {
		t.Fatalf("readEnvKeys: %v", err)
	}
	want := []string{initial}
	for key := range keys {
		want = append(want, key)
	}
	got := append([]string{current}, splitAndTrim(previous)...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != rotations+1 || !slicesEqual(got, want) {
		t.Fatalf("rotation history lost keys: got %d, want %d", len(got), len(want))
	}

	envPathLockRegistry.Lock()
	registrySize := len(envPathLockRegistry.locks)
	envPathLockRegistry.Unlock()
	if registrySize != 0 {
		t.Fatalf("path lock registry retained %d entries", registrySize)
	}
}

// TestEnvAssignmentParser guards supported dotenv syntax and comment boundaries.
func TestEnvAssignmentParser(t *testing.T) {
	tests := []struct {
		line  string
		key   string
		value string
		ok    bool
	}{
		{line: "APP_KEY=value", key: "APP_KEY", value: "value", ok: true},
		{line: " export APP_KEY = \"value\" # note", key: "APP_KEY", value: "value", ok: true},
		{line: "\tAPP_PREVIOUS_KEYS='a,b'", key: "APP_PREVIOUS_KEYS", value: "a,b", ok: true},
		{line: "VALUE=with#hash", key: "VALUE", value: "with#hash", ok: true},
		{line: "VALUE=with # comment", key: "VALUE", value: "with", ok: true},
		{line: "# APP_KEY=comment", ok: false},
		{line: "exported=value", key: "exported", value: "value", ok: true},
		{line: "export APP_KEY=\"unterminated", ok: false},
		{line: "9KEY=value", ok: false},
	}
	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			assignment, ok := parseEnvAssignment(test.line)
			if ok != test.ok || assignment.key != test.key || assignment.value != test.value {
				t.Fatalf("parseEnvAssignment = %#v, %v", assignment, ok)
			}
		})
	}
}

// TestReadEnvKeysUsesLastActiveAssignment guards dotenv precedence and missing-file behavior.
func TestReadEnvKeysUsesLastActiveAssignment(t *testing.T) {
	envPath := writeTestEnv(t, "# APP_KEY=ignored\nAPP_KEY=first\nexport APP_KEY = 'last' # selected\nAPP_PREVIOUS_KEYS = \"a,b\"\n", 0o600)
	current, previous, err := readEnvKeys(envPath)
	if err != nil || current != "last" || previous != "a,b" {
		t.Fatalf("readEnvKeys = %q, %q, %v", current, previous, err)
	}
	missing := filepath.Join(t.TempDir(), ".env")
	current, previous, err = readEnvKeys(missing)
	if err != nil || current != "" || previous != "" {
		t.Fatalf("missing readEnvKeys = %q, %q, %v", current, previous, err)
	}
}

// TestPrependUniqueDeduplicatesEntireHistory guards stable key-history ordering and deduplication.
func TestPrependUniqueDeduplicatesEntireHistory(t *testing.T) {
	if got, want := prependUnique("a", "b,a,b,c,,c"), "a,b,c"; got != want {
		t.Fatalf("prependUnique = %q, want %q", got, want)
	}
	if got := prependUnique("a", ""); got != "a" {
		t.Fatalf("prependUnique empty = %q", got)
	}
	if keys := splitAndTrim(" a, ,b , c "); !slicesEqual(keys, []string{"a", "b", "c"}) {
		t.Fatalf("splitAndTrim = %v", keys)
	}
	if keys := splitAndTrim(""); keys != nil {
		t.Fatalf("splitAndTrim empty = %#v", keys)
	}
}

// TestEnvPathPolicyRejectsSymlinksAndNonRegularFiles guards the final-path mutation boundary.
func TestEnvPathPolicyRejectsSymlinksAndNonRegularFiles(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("APP_KEY=old\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	link := filepath.Join(directory, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := GenerateKeyToEnv(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("GenerateKeyToEnv symlink error = %v", err)
	}
	if got := readTestEnv(t, target); got != "APP_KEY=old\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
	if _, err := GenerateKeyToEnv(directory); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("GenerateKeyToEnv directory error = %v", err)
	}
}

// TestRotateKeyInEnvRequiresCurrentKey guards rotation from creating history without a source key.
func TestRotateKeyInEnvRequiresCurrentKey(t *testing.T) {
	envPath := writeTestEnv(t, "FOO=bar\n", 0o600)
	if _, err := RotateKeyInEnv(envPath); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("RotateKeyInEnv missing key error = %v", err)
	}
	missing := filepath.Join(t.TempDir(), ".env")
	if _, err := RotateKeyInEnv(missing); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("RotateKeyInEnv missing file error = %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RotateKeyInEnv created missing file: %v", err)
	}
}

// TestRotateKeyInEnvValidatesHistoryBeforeGenerating guards invalid history from consuming entropy or mutating files.
func TestRotateKeyInEnvValidatesHistoryBeforeGenerating(t *testing.T) {
	newKey := envTestKey(9)
	tests := map[string]string{
		"current":  "APP_KEY=garbage\n",
		"previous": "APP_KEY=" + envTestKey(1) + "\nAPP_PREVIOUS_KEYS=" + envTestKey(2) + ",garbage\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			envPath := writeTestEnv(t, content, 0o600)
			entropy := &countingEntropy{key: newKey}
			if _, err := rotateKeyInEnv(osEnvFileSystem{}, envPath, entropy); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("rotateKeyInEnv invalid history error = %v", err)
			}
			if entropy.calls != 0 {
				t.Fatalf("entropy consumed %d times", entropy.calls)
			}
			if got := readTestEnv(t, envPath); got != content {
				t.Fatalf("invalid history changed env: %q", got)
			}
		})
	}
}

// TestEnvMutationRejectsInvalidGeneratedKey guards injected entropy results before filesystem mutation.
func TestEnvMutationRejectsInvalidGeneratedKey(t *testing.T) {
	for name, mutate := range map[string]func(string) (string, error){
		"generate": func(path string) (string, error) {
			return generateKeyToEnv(osEnvFileSystem{}, path, staticEntropy{key: "garbage"})
		},
		"rotate": func(path string) (string, error) {
			return rotateKeyInEnv(osEnvFileSystem{}, path, staticEntropy{key: "garbage"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			content := "APP_KEY=" + envTestKey(1) + "\n"
			envPath := writeTestEnv(t, content, 0o600)
			if _, err := mutate(envPath); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("invalid generated key error = %v", err)
			}
			if got := readTestEnv(t, envPath); got != content {
				t.Fatalf("invalid generated key changed env: %q", got)
			}
		})
	}
}

// TestEnvEntropyFailuresLeaveOriginalUntouched guards existing files against key-generation failures.
func TestEnvEntropyFailuresLeaveOriginalUntouched(t *testing.T) {
	envPath := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
	want := readTestEnv(t, envPath)
	entropyError := errors.New("entropy failed")
	if _, err := generateKeyToEnv(osEnvFileSystem{}, envPath, staticEntropy{err: entropyError}); !errors.Is(err, entropyError) {
		t.Fatalf("generateKeyToEnv entropy error = %v", err)
	}
	if _, err := rotateKeyInEnv(osEnvFileSystem{}, envPath, readerSource{reader: failingReader{}}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("rotateKeyInEnv entropy error = %v", err)
	}
	if got := readTestEnv(t, envPath); got != want {
		t.Fatalf("entropy failure changed env: %q", got)
	}
	assertNoEnvTemps(t, envPath)
}

// TestAtomicReplacementPreRenameFailuresCleanUp guards every preparation stage against partial replacement.
func TestAtomicReplacementPreRenameFailuresCleanUp(t *testing.T) {
	injected := errors.New("injected failure")
	tests := map[string]faultFileSystem{
		"create": {
			envFileSystem: osEnvFileSystem{},
			createError:   injected,
		},
		"chmod": {
			envFileSystem: osEnvFileSystem{},
			temporary: func(file envTemporaryFile) envTemporaryFile {
				return &faultTemporaryFile{envTemporaryFile: file, chmodError: injected}
			},
		},
		"write": {
			envFileSystem: osEnvFileSystem{},
			temporary: func(file envTemporaryFile) envTemporaryFile {
				return &faultTemporaryFile{envTemporaryFile: file, writeError: injected}
			},
		},
		"sync": {
			envFileSystem: osEnvFileSystem{},
			temporary: func(file envTemporaryFile) envTemporaryFile {
				return &faultTemporaryFile{envTemporaryFile: file, syncError: injected}
			},
		},
		"close": {
			envFileSystem: osEnvFileSystem{},
			temporary: func(file envTemporaryFile) envTemporaryFile {
				return &faultTemporaryFile{envTemporaryFile: file, closeError: injected}
			},
		},
		"rename": {
			envFileSystem: osEnvFileSystem{},
			renameError:   injected,
		},
	}
	for name, fileSystem := range tests {
		t.Run(name, func(t *testing.T) {
			oldKey := envTestKey(1)
			envPath := writeTestEnv(t, "APP_KEY="+oldKey+"\n", 0o600)
			if _, err := rotateKeyInEnv(fileSystem, envPath, staticEntropy{key: envTestKey(2)}); !errors.Is(err, injected) {
				t.Fatalf("rotateKeyInEnv error = %v", err)
			}
			if got := readTestEnv(t, envPath); got != "APP_KEY="+oldKey+"\n" {
				t.Fatalf("pre-rename failure changed env: %q", got)
			}
			assertNoEnvTemps(t, envPath)
		})
	}
}

// TestAtomicReplacementJoinsCleanupFailures guards primary and cleanup error identities against loss.
func TestAtomicReplacementJoinsCleanupFailures(t *testing.T) {
	writeError := errors.New("write failed")
	closeError := errors.New("cleanup close failed")
	removeError := errors.New("cleanup remove failed")
	fileSystem := faultFileSystem{
		envFileSystem: osEnvFileSystem{},
		removeError:   removeError,
		temporary: func(file envTemporaryFile) envTemporaryFile {
			return &faultTemporaryFile{
				envTemporaryFile: file,
				writeError:       writeError,
				closeError:       closeError,
			}
		},
	}
	envPath := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
	_, err := rotateKeyInEnv(fileSystem, envPath, staticEntropy{key: envTestKey(2)})
	for _, expected := range []error{writeError, closeError, removeError} {
		if !errors.Is(err, expected) {
			t.Fatalf("joined cleanup error %v does not contain %v", err, expected)
		}
	}
	if got := readTestEnv(t, envPath); got != "APP_KEY="+envTestKey(1)+"\n" {
		t.Fatalf("cleanup failure changed env: %q", got)
	}
	assertNoEnvTemps(t, envPath)
}

// TestAtomicReplacementReportsDirectoryDurabilityFailures guards post-commit durability error reporting.
func TestAtomicReplacementReportsDirectoryDurabilityFailures(t *testing.T) {
	injected := errors.New("directory failure")
	tests := map[string]faultFileSystem{
		"open": {
			envFileSystem: osEnvFileSystem{},
			openError:     injected,
		},
		"sync": {
			envFileSystem: osEnvFileSystem{},
			directory: func(file envSyncFile) envSyncFile {
				return &faultSyncFile{envSyncFile: file, syncError: injected}
			},
		},
		"close": {
			envFileSystem: osEnvFileSystem{},
			directory: func(file envSyncFile) envSyncFile {
				return &faultSyncFile{envSyncFile: file, closeError: injected}
			},
		},
	}
	for name, fileSystem := range tests {
		t.Run(name, func(t *testing.T) {
			envPath := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
			newKey := envTestKey(2)
			gotKey, err := rotateKeyInEnv(fileSystem, envPath, staticEntropy{key: newKey})
			if !errors.Is(err, injected) {
				t.Fatalf("rotateKeyInEnv error = %v", err)
			}
			if gotKey != newKey {
				t.Fatalf("committed key = %q, want %q", gotKey, newKey)
			}
			if got := readTestEnv(t, envPath); !strings.Contains(got, "APP_KEY="+newKey) {
				t.Fatalf("post-rename failure did not install replacement: %q", got)
			}
			assertNoEnvTemps(t, envPath)
		})
	}
}

// TestGenerateReturnsCommittedKeyWithDurabilityError guards callers from losing installed key material.
func TestGenerateReturnsCommittedKeyWithDurabilityError(t *testing.T) {
	injected := errors.New("directory open failed")
	fileSystem := faultFileSystem{envFileSystem: osEnvFileSystem{}, openError: injected}
	envPath := filepath.Join(t.TempDir(), ".env")
	newKey := envTestKey(7)
	gotKey, err := generateKeyToEnv(fileSystem, envPath, staticEntropy{key: newKey})
	if gotKey != newKey || !errors.Is(err, injected) {
		t.Fatalf("generateKeyToEnv committed result = %q, %v", gotKey, err)
	}
	if got := readTestEnv(t, envPath); got != "APP_KEY="+newKey+"\n" {
		t.Fatalf("committed generate content = %q", got)
	}
}

// TestAtomicReplacementDetectsExternalEdit guards unrelated modifications from being overwritten.
func TestAtomicReplacementDetectsExternalEdit(t *testing.T) {
	oldKey := envTestKey(1)
	externalKey := envTestKey(3)
	envPath := writeTestEnv(t, "APP_KEY="+oldKey+"\n", 0o600)
	fileSystem := &mutatingFileSystem{
		envFileSystem: osEnvFileSystem{},
		path:          envPath,
		replacement:   []byte("APP_KEY=" + externalKey + "\n"),
	}
	if _, err := rotateKeyInEnv(fileSystem, envPath, staticEntropy{key: envTestKey(2)}); err == nil || !strings.Contains(err.Error(), "changed during update") {
		t.Fatalf("rotateKeyInEnv conflict error = %v", err)
	}
	if got := readTestEnv(t, envPath); got != "APP_KEY="+externalKey+"\n" {
		t.Fatalf("conflict overwrote external edit: %q", got)
	}
	assertNoEnvTemps(t, envPath)
}

// TestLoadEnvFileSurfacesInspectionAndReadFailures guards filesystem errors against accidental suppression.
func TestLoadEnvFileSurfacesInspectionAndReadFailures(t *testing.T) {
	injected := errors.New("filesystem failed")
	path := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
	for name, fileSystem := range map[string]envFileSystem{
		"inspect": faultFileSystem{envFileSystem: osEnvFileSystem{}, lstatError: injected},
		"read":    faultFileSystem{envFileSystem: osEnvFileSystem{}, readError: injected},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadEnvFile(fileSystem, path); !errors.Is(err, injected) {
				t.Fatalf("loadEnvFile error = %v", err)
			}
		})
	}
	if _, _, err := readEnvKeys(t.TempDir()); err == nil {
		t.Fatal("readEnvKeys accepted a directory")
	}
}

// TestVerifyEnvFileUnchangedDetectsMetadataAndIdentityChanges guards snapshot conflict detection.
func TestVerifyEnvFileUnchangedDetectsMetadataAndIdentityChanges(t *testing.T) {
	base := osEnvFileSystem{}

	t.Run("mode", func(t *testing.T) {
		path := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatalf("chmod env: %v", err)
		}
		if err := verifyEnvFileUnchanged(base, path, snapshot); err == nil {
			t.Fatal("mode change was not detected")
		}
	})

	t.Run("removed", func(t *testing.T) {
		path := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove env: %v", err)
		}
		if err := verifyEnvFileUnchanged(base, path, snapshot); err == nil {
			t.Fatal("removed file was not detected")
		}
	})

	t.Run("replaced", func(t *testing.T) {
		path := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		replacement := filepath.Join(filepath.Dir(path), "replacement")
		if err := os.WriteFile(replacement, snapshot.data, snapshot.mode); err != nil {
			t.Fatalf("replace env: %v", err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatalf("install replacement env: %v", err)
		}
		if err := verifyEnvFileUnchanged(base, path, snapshot); err == nil {
			t.Fatal("identity change was not detected")
		}
	})

	t.Run("appeared", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".env")
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		if err := os.WriteFile(path, []byte("APP_KEY="+envTestKey(1)+"\n"), 0o600); err != nil {
			t.Fatalf("create env: %v", err)
		}
		if err := verifyEnvFileUnchanged(base, path, snapshot); err == nil {
			t.Fatal("appeared file was not detected")
		}
	})

	t.Run("reinspect_error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".env")
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		injected := errors.New("reinspect failed")
		fileSystem := faultFileSystem{envFileSystem: base, lstatError: injected}
		if err := verifyEnvFileUnchanged(fileSystem, path, snapshot); !errors.Is(err, injected) {
			t.Fatalf("verifyEnvFileUnchanged error = %v", err)
		}
	})

	t.Run("reread_error", func(t *testing.T) {
		path := writeTestEnv(t, "APP_KEY="+envTestKey(1)+"\n", 0o600)
		snapshot, err := loadEnvFile(base, path)
		if err != nil {
			t.Fatalf("loadEnvFile: %v", err)
		}
		injected := errors.New("reread failed")
		fileSystem := faultFileSystem{envFileSystem: base, readError: injected}
		if err := verifyEnvFileUnchanged(fileSystem, path, snapshot); !errors.Is(err, injected) {
			t.Fatalf("verifyEnvFileUnchanged error = %v", err)
		}
	})
}

// TestGenerateKeyToEnvSurfacesPathAndWriteErrors guards invalid destination failures against suppression.
func TestGenerateKeyToEnvSurfacesPathAndWriteErrors(t *testing.T) {
	missingParent := filepath.Join(t.TempDir(), "missing", ".env")
	if _, err := GenerateKeyToEnv(missingParent); err == nil {
		t.Fatal("GenerateKeyToEnv missing parent succeeded")
	}
	assertNoEnvTemps(t, missingParent)
}

// TestWriteAllRejectsZeroProgress guards atomic preparation against infinite short-write loops.
func TestWriteAllRejectsZeroProgress(t *testing.T) {
	if err := writeAll(zeroWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAll error = %v", err)
	}
	var buffer bytes.Buffer
	if err := writeAll(&buffer, []byte("data")); err != nil || buffer.String() != "data" {
		t.Fatalf("writeAll buffer = %q, %v", buffer.String(), err)
	}
}

// slicesEqual compares sorted key lists without introducing a module dependency.
func slicesEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
