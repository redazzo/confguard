package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	secretSuffix = ".secret"
	clearSuffix  = ".clr"
	encSuffix    = ".enc"
)

type ConfigNode struct {
	Key      string                 // Node's key
	Value    string                 // Value if it's a leaf node
	Children map[string]*ConfigNode // Child nodes
	Order    []string               // Order of child keys
	IsSecret bool                   // Whether this node contains a secret value
	IsArray  bool                   // Whether this node is an array
	Array    []string               // Array values if this is an array node
}

// Configuration represents the structure for handling different config file formats
type Configuration struct {
	Root       *ConfigNode
	format     string
	emptyLines map[int]bool
}

func NewConfigNode(key string) *ConfigNode {
	return &ConfigNode{
		Key:      key,
		Children: make(map[string]*ConfigNode),
		Order:    make([]string, 0),
	}
}

// CryptoManager handles encryption/decryption operations
type CryptoManager struct {
	key []byte
}

// NewCryptoManager creates a new crypto manager with the provided key
func NewCryptoManager(keyFile string) (*CryptoManager, error) {
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Ensure key is exactly 32 bytes for AES-256
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes")
	}

	return &CryptoManager{key: key}, nil
}

// Encrypt encrypts the given plaintext using AES-GCM
func (cm *CryptoManager) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(cm.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM
func (cm *CryptoManager) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cm.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "ciphertext too short", nil
	}

	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// LoadConfiguration loads a configuration file into memory
func LoadConfiguration(filename string) (*Configuration, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	config := &Configuration{
		Root:       NewConfigNode(""),
		format:     filepath.Ext(strings.TrimSuffix(filename, filepath.Ext(filename))),
		emptyLines: make(map[int]bool),
	}

	switch config.format {
	case ".yaml":
		var rootNode yaml.Node
		if err := yaml.Unmarshal(data, &rootNode); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}

		if len(rootNode.Content) > 0 {
			err = config.processYAMLNode(rootNode.Content[0], config.Root)
			if err != nil {
				return nil, err
			}
		}

		// Track empty lines
		lines := strings.Split(string(data), "\n")
		lastLineEmpty := false
		entryIndex := 0

		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				lastLineEmpty = true
				continue
			}
			if lastLineEmpty {
				config.emptyLines[entryIndex] = true
			}
			entryIndex++
			lastLineEmpty = false
		}

	case ".env":
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineNum := 0
		lastLineEmpty := false

		for scanner.Scan() {
			line := scanner.Text()
			trimmedLine := strings.TrimSpace(line)

			// Handle empty lines and comments
			if trimmedLine == "" {
				lastLineEmpty = true
				continue
			}

			if lastLineEmpty {
				config.emptyLines[lineNum] = true
			}
			lastLineEmpty = false

			if strings.HasPrefix(trimmedLine, "#") {
				// Store comments in a special node to preserve them
				commentNode := NewConfigNode(fmt.Sprintf("__comment_%d", lineNum))
				commentNode.Value = line
				config.Root.Children[commentNode.Key] = commentNode
				config.Root.Order = append(config.Root.Order, commentNode.Key)
				lineNum++
				continue
			}

			// Process environment variable
			if parts := strings.SplitN(trimmedLine, "=", 2); len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Remove quotes if present
				value = strings.Trim(value, `"'`)

				isSecret := strings.HasSuffix(key, secretSuffix)
				if isSecret {
					key = strings.TrimSuffix(key, secretSuffix)
				}

				node := NewConfigNode(key)
				node.Value = value
				node.IsSecret = isSecret
				config.Root.Children[key] = node
				config.Root.Order = append(config.Root.Order, key)
				lineNum++
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading .env file: %w", err)
		}
	}

	return config, nil
}

func (c *Configuration) processYAMLNode(node *yaml.Node, configNode *ConfigNode) error {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		key := keyNode.Value
		isSecret := strings.HasSuffix(key, secretSuffix)
		if isSecret {
			key = strings.TrimSuffix(key, secretSuffix)
		}

		child := NewConfigNode(key)
		child.IsSecret = isSecret
		configNode.Children[key] = child
		configNode.Order = append(configNode.Order, key)

		switch valueNode.Kind {
		case yaml.ScalarNode:
			child.Value = valueNode.Value

		case yaml.SequenceNode:
			child.IsArray = true
			child.Array = make([]string, 0, len(valueNode.Content))
			for _, item := range valueNode.Content {
				if item.Kind == yaml.ScalarNode {
					child.Array = append(child.Array, item.Value)
				}
			}

		case yaml.MappingNode:
			if err := c.processYAMLNode(valueNode, child); err != nil {
				return err
			}
		}
	}

	return nil
}

// SaveConfiguration saves the configuration to a file
func (c *Configuration) SaveTo(filename string) error {
	var output strings.Builder

	switch c.format {
	case ".yaml":
		if err := c.writeYAMLNode(&output, c.Root, 0); err != nil {
			return err
		}
	case ".env":
		if err := c.writeEnvNode(&output, c.Root); err != nil {
			return err
		}
	}

	outputStr := output.String()
	if outputStr == "" {
		return fmt.Errorf("generated empty output for file %s", filename)
	}

	// Ensure proper line endings but preserve intentional empty lines
	outputStr = strings.TrimSpace(outputStr) + "\n"

	if err := ioutil.WriteFile(filename, []byte(outputStr), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}

	fmt.Printf("Successfully wrote %s (%d bytes)\n", filename, len(outputStr))
	return nil
}

func (c *Configuration) writeYAMLNode(output *strings.Builder, node *ConfigNode, depth int) error {
	indent := strings.Repeat("  ", depth)

	for i, key := range node.Order {
		child := node.Children[key]

		// Add empty line between sections
		if depth == 0 && i > 0 {
			output.WriteString("\n")
		}

		if strings.HasPrefix(child.Key, "__comment_") {
			output.WriteString(child.Value + "\n")
			continue
		}

		if child.IsArray {
			output.WriteString(fmt.Sprintf("%s%s:\n", indent, child.Key))
			// Handle empty arrays
			if len(child.Array) == 0 {
				continue
			}
			// Write array items
			for _, item := range child.Array {
				output.WriteString(fmt.Sprintf("%s  - %s\n", indent, item))
			}
		} else if len(child.Children) > 0 {
			output.WriteString(fmt.Sprintf("%s%s:\n", indent, child.Key))
			if err := c.writeYAMLNode(output, child, depth+1); err != nil {
				return err
			}
		} else {
			value := child.Value
			outputKey := child.Key
			if child.IsSecret {
				outputKey += secretSuffix
			}
			output.WriteString(fmt.Sprintf("%s%s: %s\n", indent, outputKey, value))
		}
	}

	return nil
}

func (c *Configuration) writeEnvNode(output *strings.Builder, node *ConfigNode) error {
	for i, key := range node.Order {
		child := node.Children[key]

		// Add empty line if marked
		if c.emptyLines[i] {
			output.WriteString("\n")
		}

		// Handle comments
		if strings.HasPrefix(child.Key, "__comment_") {
			output.WriteString(child.Value + "\n")
			continue
		}

		// Handle regular entries
		outputKey := child.Key
		if child.IsSecret {
			outputKey += secretSuffix
		}

		// Quote values containing spaces or special characters
		value := child.Value
		if strings.ContainsAny(value, " #'\"\\") {
			value = fmt.Sprintf("\"%s\"", strings.ReplaceAll(value, "\"", "\\\""))
		}

		output.WriteString(fmt.Sprintf("%s=%s\n", outputKey, value))
	}

	return nil
}

func handleEncrypt(filename string) error {
	cm, err := NewCryptoManager("config_secret")
	if err != nil {
		return fmt.Errorf("crypto manager initialization failed: %w", err)
	}

	config, err := LoadConfiguration(filename)
	if err != nil {
		return err
	}

	encConfig := &Configuration{
		Root:       NewConfigNode(""),
		format:     config.format,
		emptyLines: config.emptyLines,
	}

	var encryptNode func(*ConfigNode, *ConfigNode) error
	encryptNode = func(src, dst *ConfigNode) error {
		dst.Key = src.Key
		dst.Order = append([]string{}, src.Order...)
		dst.IsArray = src.IsArray
		dst.Array = append([]string{}, src.Array...)

		for _, key := range src.Order {
			child := src.Children[key]
			dstChild := NewConfigNode(key)
			dst.Children[key] = dstChild

			if child.IsArray {
				dstChild.IsArray = true
				dstChild.Array = append([]string{}, child.Array...)
			} else if len(child.Children) > 0 {
				if err := encryptNode(child, dstChild); err != nil {
					return err
				}
			} else {
				dstChild.IsSecret = child.IsSecret
				if child.IsSecret {
					encValue, err := cm.Encrypt(child.Value)
					if err != nil {
						return fmt.Errorf("failed to encrypt value for key %s: %w", child.Key, err)
					}
					dstChild.Value = encValue
				} else {
					dstChild.Value = child.Value
				}
			}
		}
		return nil
	}

	if err := encryptNode(config.Root, encConfig.Root); err != nil {
		return err
	}

	baseFile := strings.TrimSuffix(filename, clearSuffix)
	return encConfig.SaveTo(baseFile + encSuffix)
}

func handleDecrypt(filename string) error {
	cm, err := NewCryptoManager("config_secret")
	if err != nil {
		return fmt.Errorf("crypto manager initialization failed: %w", err)
	}

	config, err := LoadConfiguration(filename)
	if err != nil {
		return err
	}

	decConfig := &Configuration{
		Root:       NewConfigNode(""),
		format:     config.format,
		emptyLines: config.emptyLines,
	}

	var decryptNode func(*ConfigNode, *ConfigNode) error
	decryptNode = func(src, dst *ConfigNode) error {
		dst.Key = src.Key
		dst.Order = append([]string{}, src.Order...)
		dst.IsArray = src.IsArray
		dst.Array = append([]string{}, src.Array...)

		for _, key := range src.Order {
			child := src.Children[key]
			dstChild := NewConfigNode(key)
			dst.Children[key] = dstChild

			if child.IsArray {
				dstChild.IsArray = true
				dstChild.Array = append([]string{}, child.Array...)
			} else if len(child.Children) > 0 {
				if err := decryptNode(child, dstChild); err != nil {
					return err
				}
			} else {
				// For decryption, we remove the .secret suffix
				if child.IsSecret {
					decValue, err := cm.Decrypt(child.Value)
					if err != nil {
						return fmt.Errorf("failed to decrypt value for key %s: %w", child.Key, err)
					}
					dstChild.Value = decValue
					dstChild.IsSecret = false // Remove secret flag for decrypted output
				} else {
					dstChild.Value = child.Value
				}
			}
		}
		return nil
	}

	if err := decryptNode(config.Root, decConfig.Root); err != nil {
		return err
	}

	baseFile := strings.TrimSuffix(filename, encSuffix)
	return decConfig.SaveTo(baseFile)
}

func handleRegen(filename string) error {
	cm, err := NewCryptoManager("config_secret")
	if err != nil {
		return fmt.Errorf("crypto manager initialization failed: %w", err)
	}

	config, err := LoadConfiguration(filename)
	if err != nil {
		return err
	}

	regenConfig := &Configuration{
		Root:       NewConfigNode(""),
		format:     config.format,
		emptyLines: config.emptyLines,
	}

	var regenNode func(*ConfigNode, *ConfigNode) error
	regenNode = func(src, dst *ConfigNode) error {
		dst.Key = src.Key
		dst.Order = append([]string{}, src.Order...)
		dst.IsArray = src.IsArray
		dst.Array = append([]string{}, src.Array...)

		for _, key := range src.Order {
			child := src.Children[key]
			dstChild := NewConfigNode(key)
			dst.Children[key] = dstChild

			if child.IsArray {
				dstChild.IsArray = true
				dstChild.Array = append([]string{}, child.Array...)
			} else if len(child.Children) > 0 {
				if err := regenNode(child, dstChild); err != nil {
					return err
				}
			} else {
				dstChild.IsSecret = child.IsSecret // Maintain secret flag for regeneration
				if child.IsSecret {
					decValue, err := cm.Decrypt(child.Value)
					if err != nil {
						return fmt.Errorf("failed to decrypt value for key %s: %w", child.Key, err)
					}
					dstChild.Value = decValue
				} else {
					dstChild.Value = child.Value
				}
			}
		}
		return nil
	}

	if err := regenNode(config.Root, regenConfig.Root); err != nil {
		return err
	}

	baseFile := strings.TrimSuffix(filename, encSuffix)
	return regenConfig.SaveTo(baseFile + clearSuffix)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "confguard",
		Short: "Secure configuration file management",
		Long: `
ConfGuard is a utility for protecting sensitive .env or yaml configuration files.
It encrypts values marked as secrets, allowing secure storage in version control systems.

Example usage:
  "confguard encrypt config.yaml.clr" - creates a config.yaml.enc file that has encrypted values for keys marked with .secret.
  "confguard decrypt config.yaml.enc" - creates a config.yaml file with decrypted values.
  "confguard regen config.yaml.enc"   - creates a config.yaml.clr file that can be edited and re-encrypted.`,
	}

	var encryptCmd = &cobra.Command{
		Use:   "encrypt [file]",
		Short: "Encrypt a .clr configuration file",
		Long: `Encrypt a .clr configuration file, producing a .enc file.
Only values with keys ending in .secret will be encrypted.
Example: confguard encrypt config.yaml.clr`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]
			if !strings.HasSuffix(filename, clearSuffix) {
				return fmt.Errorf("input file must have .clr suffix, got: %s", filename)
			}
			return handleEncrypt(filename)
		},
	}

	var decryptCmd = &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .enc configuration file",
		Long: `Decrypt a .enc configuration file, producing a clean configuration file.
The .secret suffix will be removed from key names in the output.
Example: confguard decrypt config.yaml.enc`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]
			if !strings.HasSuffix(filename, encSuffix) {
				return fmt.Errorf("input file must have .enc suffix, got: %s", filename)
			}
			return handleDecrypt(filename)
		},
	}

	var regenCmd = &cobra.Command{
		Use:   "regen [file]",
		Short: "Regenerate .clr file from .enc file",
		Long: `Regenerate a .clr file from a .enc file.
This is useful when you need to update configuration values.
Example: confguard regen config.yaml.enc`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]
			if !strings.HasSuffix(filename, encSuffix) {
				return fmt.Errorf("input file must have .enc suffix, got: %s", filename)
			}
			return handleRegen(filename)
		},
	}

	rootCmd.AddCommand(encryptCmd, decryptCmd, regenCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
