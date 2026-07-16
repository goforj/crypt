package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	appKeyName         = "APP_KEY"
	appPreviousKeyName = "APP_PREVIOUS_KEYS"
)

// envPathLock serializes one normalized path while allowing unrelated env files to proceed independently.
type envPathLock struct {
	mutex      sync.Mutex
	references int
}

// envPathLockRegistry avoids leaking one mutex for every path ever touched by the process.
var envPathLockRegistry = struct {
	sync.Mutex
	locks map[string]*envPathLock
}{
	locks: make(map[string]*envPathLock),
}

// envLine retains the exact line ending so mixed or CRLF files are not normalized.
type envLine struct {
	text   string
	ending string
}

// envDocument preserves unrelated bytes while canonicalizing assignments owned by this package.
type envDocument struct {
	lines           []envLine
	preferredEnding string
	trailingEnding  bool
}

// envAssignment identifies an active dotenv assignment and its replaceable value span.
type envAssignment struct {
	key        string
	value      string
	valueStart int
	valueEnd   int
}

// envFileSnapshot binds the parsed contents to the file identity used for conflict detection.
type envFileSnapshot struct {
	document envDocument
	data     []byte
	info     os.FileInfo
	exists   bool
	mode     os.FileMode
}

// envTemporaryFile is the subset needed to durably prepare an atomic replacement.
type envTemporaryFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

// envSyncFile is the subset needed to make a directory rename durable.
type envSyncFile interface {
	Sync() error
	Close() error
}

// envFileSystem makes failure stages deterministic in tests without mutable package hooks.
type envFileSystem interface {
	Lstat(string) (os.FileInfo, error)
	ReadFile(string) ([]byte, error)
	CreateTemp(string, string) (envTemporaryFile, error)
	Rename(string, string) error
	Remove(string) error
	Open(string) (envSyncFile, error)
}

// osEnvFileSystem delegates env-file operations to the standard library.
type osEnvFileSystem struct{}

// Lstat inspects the path itself so final-component symlinks can be rejected.
func (osEnvFileSystem) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

// ReadFile reads a regular env file after Lstat has established the path policy.
func (osEnvFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// CreateTemp creates the replacement in the destination directory for an atomic rename.
func (osEnvFileSystem) CreateTemp(dir, pattern string) (envTemporaryFile, error) {
	return os.CreateTemp(dir, pattern)
}

// Rename atomically installs the fully synced temporary file on supported filesystems.
func (osEnvFileSystem) Rename(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

// Remove cleans a temporary file after any pre-rename failure.
func (osEnvFileSystem) Remove(name string) error {
	return os.Remove(name)
}

// Open opens the containing directory so the rename can be synced.
func (osEnvFileSystem) Open(name string) (envSyncFile, error) {
	return os.Open(name)
}

// GenerateKeyToEnv creates a new APP_KEY and destructively clears APP_PREVIOUS_KEYS.
//
// This operation is a reset, not a graceful rotation. Existing ciphertext that
// requires a cleared previous key becomes unreadable; use RotateKeyInEnv to retain
// decryption history. New files use mode 0600, while existing file permissions are
// preserved. Final-component symlinks are rejected. If the atomic rename commits but
// syncing its directory fails, the installed key is returned together with the error.
// @group Key management
// @behavior mutates-filesystem
//
// Example: reset APP_KEY in a temporary env file
//
//	dir, _ := os.MkdirTemp("", "crypt-reset-*")
//	defer os.RemoveAll(dir)
//	envPath := filepath.Join(dir, ".env")
//	key, err := crypt.GenerateKeyToEnv(envPath)
//	godump.Dump(err, key)
//	// #error <nil>
//	// #string "base64:..."
func GenerateKeyToEnv(envPath string) (string, error) {
	normalizedPath, unlock, err := lockEnvPath(envPath)
	if err != nil {
		return "", err
	}
	defer unlock()

	return generateKeyToEnv(osEnvFileSystem{}, normalizedPath, randomSource{})
}

// RotateKeyInEnv writes a new APP_KEY and prepends the old key to APP_PREVIOUS_KEYS.
//
// Same-path calls are serialized within this process so concurrent rotations retain
// every key. Atomic replacement prevents partial files, but unrelated processes must
// still coordinate their read-modify-write operations with the caller. If the atomic
// rename commits but syncing its directory fails, the installed key is returned with
// the error so callers do not lose track of active key material.
// @group Key management
// @behavior mutates-filesystem
//
// Example: rotate APP_KEY while retaining the previous key
//
//	dir, _ := os.MkdirTemp("", "crypt-rotate-*")
//	defer os.RemoveAll(dir)
//	envPath := filepath.Join(dir, ".env")
//	currentKey, _ := crypt.GenerateAppKey()
//	// Seed a minimal .env with an existing APP_KEY.
//	_ = os.WriteFile(envPath, []byte("APP_KEY="+currentKey+"\n"), 0o600)
//	newKey, err := crypt.RotateKeyInEnv(envPath)
//	godump.Dump(err == nil, newKey != "")
//	// #bool true
//	// #bool true
func RotateKeyInEnv(envPath string) (string, error) {
	normalizedPath, unlock, err := lockEnvPath(envPath)
	if err != nil {
		return "", err
	}
	defer unlock()

	return rotateKeyInEnv(osEnvFileSystem{}, normalizedPath, randomSource{})
}

// entropySource supplies application keys while allowing deterministic failure injection.
type entropySource interface {
	Generate() (string, error)
}

// randomSource uses the package's cryptographically secure key generator.
type randomSource struct{}

// Generate creates one fresh application key from crypto/rand.
func (randomSource) Generate() (string, error) {
	return GenerateAppKey()
}

// readerSource adapts an io.Reader to entropySource for deterministic internal tests.
type readerSource struct {
	reader io.Reader
}

// Generate creates an application key from the injected reader.
func (source readerSource) Generate() (string, error) {
	return generateAppKey(source.reader)
}

// lockEnvPath normalizes and locks a path until the returned release function runs.
func lockEnvPath(envPath string) (string, func(), error) {
	normalizedPath, err := filepath.Abs(envPath)
	if err != nil {
		return "", nil, fmt.Errorf("normalize env path: %w", err)
	}
	normalizedPath = filepath.Clean(normalizedPath)

	envPathLockRegistry.Lock()
	lock := envPathLockRegistry.locks[normalizedPath]
	if lock == nil {
		lock = &envPathLock{}
		envPathLockRegistry.locks[normalizedPath] = lock
	}
	lock.references++
	envPathLockRegistry.Unlock()

	lock.mutex.Lock()
	var once sync.Once
	return normalizedPath, func() {
		once.Do(func() {
			lock.mutex.Unlock()
			envPathLockRegistry.Lock()
			lock.references--
			if lock.references == 0 {
				delete(envPathLockRegistry.locks, normalizedPath)
			}
			envPathLockRegistry.Unlock()
		})
	}, nil
}

// generateKeyToEnv performs the destructive reset with explicit filesystem and entropy dependencies.
func generateKeyToEnv(fileSystem envFileSystem, envPath string, entropy entropySource) (string, error) {
	snapshot, err := loadEnvFile(fileSystem, envPath)
	if err != nil {
		return "", err
	}

	key, err := entropy.Generate()
	if err != nil {
		return "", err
	}
	if _, err := ReadAppKey(key); err != nil {
		return "", fmt.Errorf("generated application key is invalid: %w", err)
	}
	snapshot.document.set(appKeyName, key)
	snapshot.document.remove(appPreviousKeyName)
	committed, err := replaceEnvFile(fileSystem, envPath, snapshot)
	if err != nil {
		if committed {
			return key, err
		}
		return "", err
	}
	return key, nil
}

// rotateKeyInEnv performs one locked read-modify-write rotation.
func rotateKeyInEnv(fileSystem envFileSystem, envPath string, entropy entropySource) (string, error) {
	snapshot, err := loadEnvFile(fileSystem, envPath)
	if err != nil {
		return "", err
	}
	current, previous := snapshot.document.keys()
	if current == "" {
		return "", fmt.Errorf("%w: APP_KEY not found; cannot rotate", ErrInvalidKey)
	}
	if err := validateRotationKeys(current, previous); err != nil {
		return "", err
	}

	newKey, err := entropy.Generate()
	if err != nil {
		return "", err
	}
	if _, err := ReadAppKey(newKey); err != nil {
		return "", fmt.Errorf("generated application key is invalid: %w", err)
	}
	snapshot.document.set(appKeyName, newKey)
	snapshot.document.set(appPreviousKeyName, prependUnique(current, previous))
	committed, err := replaceEnvFile(fileSystem, envPath, snapshot)
	if err != nil {
		if committed {
			return newKey, err
		}
		return "", err
	}
	return newKey, nil
}

// validateRotationKeys prevents a successful rotation from preserving history that NewFromEnv cannot parse.
func validateRotationKeys(current, previous string) error {
	if _, err := ReadAppKey(current); err != nil {
		return fmt.Errorf("cannot rotate invalid APP_KEY: %w", err)
	}
	for index, key := range splitAndTrim(previous) {
		if _, err := ReadAppKey(key); err != nil {
			return fmt.Errorf("cannot rotate invalid APP_PREVIOUS_KEYS entry at index %d: %w", index, err)
		}
	}
	return nil
}

// loadEnvFile enforces the regular-file and final-symlink policy before parsing.
func loadEnvFile(fileSystem envFileSystem, envPath string) (envFileSnapshot, error) {
	info, err := fileSystem.Lstat(envPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return envFileSnapshot{
				document: parseEnvDocument(nil, true),
				mode:     0o600,
			}, nil
		}
		return envFileSnapshot{}, fmt.Errorf("inspect env file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return envFileSnapshot{}, errors.New("env file symlinks are not supported")
	}
	if !info.Mode().IsRegular() {
		return envFileSnapshot{}, errors.New("env path must name a regular file")
	}

	data, err := fileSystem.ReadFile(envPath)
	if err != nil {
		return envFileSnapshot{}, fmt.Errorf("read env file: %w", err)
	}
	return envFileSnapshot{
		document: parseEnvDocument(data, len(data) == 0),
		data:     append([]byte(nil), data...),
		info:     info,
		exists:   true,
		mode:     info.Mode().Perm(),
	}, nil
}

// replaceEnvFile prepares, syncs, and atomically installs a same-directory replacement.
// Its committed result distinguishes pre-rename failures from post-rename durability errors.
func replaceEnvFile(fileSystem envFileSystem, envPath string, snapshot envFileSnapshot) (committed bool, returnErr error) {
	content := snapshot.document.bytes()
	directory := filepath.Dir(envPath)
	pattern := "." + filepath.Base(envPath) + ".tmp-*"
	temporary, err := fileSystem.CreateTemp(directory, pattern)
	if err != nil {
		return false, fmt.Errorf("create env temporary file: %w", err)
	}

	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			if err := temporary.Close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close env temporary file during cleanup: %w", err))
			}
		}
		if !committed {
			if err := fileSystem.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove env temporary file during cleanup: %w", err))
			}
		}
	}()

	if err := writeAll(temporary, content); err != nil {
		return false, fmt.Errorf("write env temporary file: %w", err)
	}
	if err := temporary.Chmod(snapshot.mode); err != nil {
		return false, fmt.Errorf("set env temporary file mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync env temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("close env temporary file: %w", err)
	}
	closed = true

	if err := verifyEnvFileUnchanged(fileSystem, envPath, snapshot); err != nil {
		return false, err
	}
	if err := fileSystem.Rename(temporaryPath, envPath); err != nil {
		return false, fmt.Errorf("replace env file: %w", err)
	}
	committed = true

	directoryFile, err := fileSystem.Open(directory)
	if err != nil {
		return true, fmt.Errorf("open env directory for sync after commit: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		return true, errors.Join(
			fmt.Errorf("sync env directory after commit: %w", err),
			closeEnvDirectory(directoryFile, "after sync failure"),
		)
	}
	if err := directoryFile.Close(); err != nil {
		return true, fmt.Errorf("close env directory after commit: %w", err)
	}
	return true, nil
}

// closeEnvDirectory gives directory cleanup errors a place in the returned error chain.
func closeEnvDirectory(directory envSyncFile, context string) error {
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close env directory %s: %w", context, err)
	}
	return nil
}

// verifyEnvFileUnchanged avoids knowingly overwriting a replaced or edited snapshot.
func verifyEnvFileUnchanged(fileSystem envFileSystem, envPath string, snapshot envFileSnapshot) error {
	info, err := fileSystem.Lstat(envPath)
	if !snapshot.exists {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reinspect env file: %w", err)
		}
		return errors.New("env file changed during update")
	}
	if err != nil {
		return fmt.Errorf("reinspect env file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(snapshot.info, info) || info.Mode().Perm() != snapshot.mode {
		return errors.New("env file changed during update")
	}
	data, err := fileSystem.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("reread env file: %w", err)
	}
	if !bytes.Equal(data, snapshot.data) {
		return errors.New("env file changed during update")
	}
	return nil
}

// writeAll handles short writes so a successful return means every byte reached the file buffer.
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// parseEnvDocument records exact newline bytes and the existing trailing-newline choice.
func parseEnvDocument(data []byte, trailingForEmpty bool) envDocument {
	document := envDocument{
		preferredEnding: "\n",
		trailingEnding:  trailingForEmpty,
	}
	for start := 0; start < len(data); {
		newlineOffset := bytes.IndexByte(data[start:], '\n')
		if newlineOffset < 0 {
			document.lines = append(document.lines, envLine{text: string(data[start:])})
			break
		}

		end := start + newlineOffset
		lineEnd := "\n"
		textEnd := end
		if end > start && data[end-1] == '\r' {
			lineEnd = "\r\n"
			textEnd--
		}
		document.lines = append(document.lines, envLine{text: string(data[start:textEnd]), ending: lineEnd})
		if len(document.lines) == 1 {
			document.preferredEnding = lineEnd
		}
		start = end + 1
	}
	if len(data) > 0 {
		document.trailingEnding = data[len(data)-1] == '\n'
	}
	return document
}

// bytes renders the document after restoring its original trailing-newline policy.
func (document *envDocument) bytes() []byte {
	document.normalizeEndings()
	var builder strings.Builder
	for _, line := range document.lines {
		builder.WriteString(line.text)
		builder.WriteString(line.ending)
	}
	return []byte(builder.String())
}

// normalizeEndings fills only newly exposed gaps and leaves retained line endings untouched.
func (document *envDocument) normalizeEndings() {
	if len(document.lines) == 0 {
		return
	}
	for index := 0; index < len(document.lines)-1; index++ {
		if document.lines[index].ending == "" {
			document.lines[index].ending = document.preferredEnding
		}
	}
	last := len(document.lines) - 1
	if document.trailingEnding {
		if document.lines[last].ending == "" {
			document.lines[last].ending = document.preferredEnding
		}
		return
	}
	document.lines[last].ending = ""
}

// keys applies common dotenv last-assignment-wins behavior while ignoring comments.
func (document envDocument) keys() (current string, previous string) {
	for _, line := range document.lines {
		assignment, ok := parseEnvAssignment(line.text)
		if !ok {
			continue
		}
		switch assignment.key {
		case appKeyName:
			current = assignment.value
		case appPreviousKeyName:
			previous = assignment.value
		}
	}
	return current, previous
}

// set updates the first active assignment's style and removes later active duplicates.
func (document *envDocument) set(key, value string) {
	updated := false
	lines := make([]envLine, 0, len(document.lines)+1)
	for _, line := range document.lines {
		assignment, ok := parseEnvAssignment(line.text)
		if !ok || assignment.key != key {
			lines = append(lines, line)
			continue
		}
		if updated {
			continue
		}
		line.text = line.text[:assignment.valueStart] + value + line.text[assignment.valueEnd:]
		lines = append(lines, line)
		updated = true
	}
	if !updated {
		lines = append(lines, envLine{text: key + "=" + value})
	}
	document.lines = lines
	document.normalizeEndings()
}

// remove deletes every active assignment while preserving commented examples and unrelated lines.
func (document *envDocument) remove(key string) {
	lines := make([]envLine, 0, len(document.lines))
	for _, line := range document.lines {
		assignment, ok := parseEnvAssignment(line.text)
		if ok && assignment.key == key {
			continue
		}
		lines = append(lines, line)
	}
	document.lines = lines
	document.normalizeEndings()
}

// parseEnvAssignment recognizes whitespace, export, quotes, and inline comments without rewriting them.
func parseEnvAssignment(line string) (envAssignment, bool) {
	index := skipEnvSpace(line, 0)
	if strings.HasPrefix(line[index:], "export") {
		afterExport := index + len("export")
		if afterExport < len(line) && isEnvSpace(line[afterExport]) {
			index = skipEnvSpace(line, afterExport)
		}
	}

	keyStart := index
	if keyStart >= len(line) || !isEnvKeyStart(line[keyStart]) {
		return envAssignment{}, false
	}
	index++
	for index < len(line) && isEnvKeyPart(line[index]) {
		index++
	}
	key := line[keyStart:index]
	index = skipEnvSpace(line, index)
	if index >= len(line) || line[index] != '=' {
		return envAssignment{}, false
	}
	index = skipEnvSpace(line, index+1)
	valueStart := index

	if index < len(line) && (line[index] == '\'' || line[index] == '"') {
		quote := line[index]
		valueStart = index + 1
		for index = valueStart; index < len(line); index++ {
			if quote == '"' && line[index] == '\\' {
				index++
				continue
			}
			if line[index] == quote {
				return envAssignment{key: key, value: line[valueStart:index], valueStart: valueStart, valueEnd: index}, true
			}
		}
		return envAssignment{}, false
	}

	valueEnd := len(line)
	for index = valueStart; index < len(line); index++ {
		if line[index] != '#' || (index > valueStart && !isEnvSpace(line[index-1])) {
			continue
		}
		valueEnd = index
		for valueEnd > valueStart && isEnvSpace(line[valueEnd-1]) {
			valueEnd--
		}
		break
	}
	for valueEnd > valueStart && isEnvSpace(line[valueEnd-1]) {
		valueEnd--
	}
	return envAssignment{key: key, value: line[valueStart:valueEnd], valueStart: valueStart, valueEnd: valueEnd}, true
}

// skipEnvSpace advances over dotenv's horizontal assignment whitespace.
func skipEnvSpace(value string, index int) int {
	for index < len(value) && isEnvSpace(value[index]) {
		index++
	}
	return index
}

// isEnvSpace restricts formatting recognition to horizontal space within one parsed line.
func isEnvSpace(value byte) bool {
	return value == ' ' || value == '\t'
}

// isEnvKeyStart follows conventional dotenv identifier syntax.
func isEnvKeyStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

// isEnvKeyPart permits digits after the first identifier byte.
func isEnvKeyPart(value byte) bool {
	return isEnvKeyStart(value) || value >= '0' && value <= '9'
}

// prependUnique puts the current key first and removes every duplicate history entry.
func prependUnique(current string, previous string) string {
	keys := make([]string, 0, 1+strings.Count(previous, ","))
	seen := make(map[string]struct{})
	for _, key := range append([]string{current}, splitAndTrim(previous)...) {
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return strings.Join(keys, ",")
}

// splitAndTrim normalizes the comma-delimited previous-key syntax without imposing a count limit.
func splitAndTrim(value string) []string {
	if value == "" {
		return nil
	}
	segments := strings.Split(value, ",")
	keys := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			keys = append(keys, segment)
		}
	}
	return keys
}

// readEnvKeys retains a focused internal reader for tests and callers inside this package.
func readEnvKeys(envPath string) (current string, previous string, err error) {
	snapshot, err := loadEnvFile(osEnvFileSystem{}, envPath)
	if err != nil {
		return "", "", err
	}
	current, previous = snapshot.document.keys()
	return current, previous, nil
}
