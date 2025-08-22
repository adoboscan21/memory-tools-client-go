package mtclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// --- Protocol Constants (Synchronized with the server) ---
const (
	// Command Types
	cmdCollectionCreate         byte = 3
	cmdCollectionDelete         byte = 4
	cmdCollectionList           byte = 5
	cmdCollectionIndexCreate    byte = 6
	cmdCollectionIndexDelete    byte = 7
	cmdCollectionIndexList      byte = 8
	cmdCollectionItemSet        byte = 9
	cmdCollectionItemSetMany    byte = 10
	cmdCollectionItemGet        byte = 11
	cmdCollectionItemDelete     byte = 12
	cmdCollectionQuery          byte = 14
	cmdCollectionItemDeleteMany byte = 15
	cmdCollectionItemUpdate     byte = 16
	cmdCollectionItemUpdateMany byte = 17
	cmdAuthenticate             byte = 18
	cmdBegin                    byte = 25
	cmdCommit                   byte = 26
	cmdRollback                 byte = 27

	// Server Response Statuses
	statusOK           = 1
	statusNotFound     = 2
	statusError        = 3
	statusBadCommand   = 4
	statusUnauthorized = 5
	statusBadRequest   = 6
)

// byteOrder is Little Endian, matching the server's protocol.
var byteOrder = binary.LittleEndian

// getStatusString converts a numeric status code to its string representation.
func getStatusString(status byte) string {
	switch status {
	case statusOK:
		return "OK"
	case statusNotFound:
		return "NOT_FOUND"
	case statusError:
		return "ERROR"
	case statusBadCommand:
		return "BAD_COMMAND"
	case statusUnauthorized:
		return "UNAUTHORIZED"
	case statusBadRequest:
		return "BAD_REQUEST"
	default:
		return "UNKNOWN_STATUS"
	}
}

// --- Response Structs ---

// CommandResponse represents a generic response from the server.
type CommandResponse struct {
	StatusCode byte
	Status     string
	Message    string
	RawData    []byte
}

// OK returns true if the command was successful.
func (r *CommandResponse) OK() bool {
	return r.StatusCode == statusOK
}

// JSON decodes the raw response data into the provided interface.
// 'v' must be a pointer.
func (r *CommandResponse) JSON(v any) error {
	if len(r.RawData) == 0 {
		return fmt.Errorf("no data to decode")
	}
	return json.Unmarshal(r.RawData, v)
}

// GetResult is a specialized response for 'get' operations for a more intuitive API.
type GetResult struct {
	*CommandResponse
}

// Found returns true if the item was found.
func (r *GetResult) Found() bool {
	return r.OK()
}

// Value decodes the item's value from JSON into the provided interface.
// 'v' must be a pointer.
func (r *GetResult) Value(v any) error {
	return r.JSON(v)
}

// --- Query Builder ---

// Query is a helper struct to build complex queries for the server.
type Query struct {
	Filter       map[string]any `json:"filter,omitempty"`
	OrderBy      []any          `json:"order_by,omitempty"`
	Limit        *int           `json:"limit,omitempty"`
	Offset       int            `json:"offset,omitempty"`
	Count        bool           `json:"count,omitempty"`
	Aggregations map[string]any `json:"aggregations,omitempty"`
	GroupBy      []string       `json:"group_by,omitempty"`
	Having       map[string]any `json:"having,omitempty"`
	Distinct     string         `json:"distinct,omitempty"`
	Projection   []string       `json:"projection,omitempty"`
	Lookups      []any          `json:"lookups,omitempty"`
}

// toJSON serializes the query object to a JSON byte slice.
func (q *Query) toJSON() ([]byte, error) {
	return json.Marshal(q)
}

// --- Main Client Struct ---

// Client is an asynchronous client to interact with a Memory Tools server.
type Client struct {
	host              string
	port              int
	username          string
	password          string
	serverCertPath    string
	insecure          bool
	conn              net.Conn
	reader            *bufio.Reader
	writer            *bufio.Writer
	mu                sync.Mutex
	authenticatedUser string
}

// ClientOptions holds the configuration for creating a new client.
type ClientOptions struct {
	Host               string
	Port               int
	Username           string
	Password           string
	ServerCertPath     string // Path to the server's public certificate (.crt)
	InsecureSkipVerify bool   // Set to true to disable server certificate validation (not recommended for production)
}

// NewClient creates a new instance of the MemoryToolsClient.
func NewClient(opts ClientOptions) *Client {
	return &Client{
		host:           opts.Host,
		port:           opts.Port,
		username:       opts.Username,
		password:       opts.Password,
		serverCertPath: opts.ServerCertPath,
		insecure:       opts.InsecureSkipVerify,
	}
}

// Connect establishes a secure connection to the server and authenticates.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Simple check to see if connection is still alive
		c.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		var one []byte
		if _, err := c.conn.Read(one); err == io.EOF {
			// Connection is dead, proceed to reconnect
			c.closeConnection()
		} else {
			// Connection is likely alive
			c.conn.SetReadDeadline(time.Time{})
			return nil
		}
	}

	// TLS Configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.insecure,
	}

	if c.serverCertPath != "" {
		caCert, err := os.ReadFile(c.serverCertPath)
		if err != nil {
			return fmt.Errorf("failed to read server certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect via TLS: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)

	if c.username != "" && c.password != "" {
		if err := c.performAuthentication(c.username, c.password); err != nil {
			c.closeConnection()
			return err
		}
	}
	return nil
}

// Close terminates the connection to the server.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeConnection()
}

// IsAuthenticated checks if the client has successfully authenticated.
func (c *Client) IsAuthenticated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticatedUser != ""
}

// --- Public API ---

// Begin starts a new transaction.
func (c *Client) Begin() (*CommandResponse, error) {
	return c.sendCommand(cmdBegin, nil)
}

// Commit commits the current transaction.
func (c *Client) Commit() (*CommandResponse, error) {
	return c.sendCommand(cmdCommit, nil)
}

// Rollback rolls back the current transaction.
func (c *Client) Rollback() (*CommandResponse, error) {
	return c.sendCommand(cmdRollback, nil)
}

// CollectionCreate creates a new collection.
func (c *Client) CollectionCreate(name string) (*CommandResponse, error) {
	payload := writeString(name)
	return c.sendCommand(cmdCollectionCreate, payload)
}

// CollectionDelete deletes a collection.
func (c *Client) CollectionDelete(name string) (*CommandResponse, error) {
	payload := writeString(name)
	return c.sendCommand(cmdCollectionDelete, payload)
}

// CollectionList lists all accessible collections.
func (c *Client) CollectionList() ([]string, error) {
	resp, err := c.sendCommand(cmdCollectionList, nil)
	if err != nil {
		return nil, err
	}
	if !resp.OK() {
		return nil, fmt.Errorf("failed to list collections: %s: %s", resp.Status, resp.Message)
	}
	var collections []string
	if err := resp.JSON(&collections); err != nil {
		return nil, fmt.Errorf("failed to parse collection list: %w", err)
	}
	return collections, nil
}

// CollectionIndexCreate creates an index on a collection field.
func (c *Client) CollectionIndexCreate(collectionName, fieldName string) (*CommandResponse, error) {
	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(fieldName))
	return c.sendCommand(cmdCollectionIndexCreate, payload.Bytes())
}

// CollectionIndexDelete deletes an index from a collection.
func (c *Client) CollectionIndexDelete(collectionName, fieldName string) (*CommandResponse, error) {
	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(fieldName))
	return c.sendCommand(cmdCollectionIndexDelete, payload.Bytes())
}

// CollectionIndexList lists all indexes on a collection.
func (c *Client) CollectionIndexList(collectionName string) ([]string, error) {
	resp, err := c.sendCommand(cmdCollectionIndexList, writeString(collectionName))
	if err != nil {
		return nil, err
	}
	if !resp.OK() {
		return nil, fmt.Errorf("failed to list indexes: %s: %s", resp.Status, resp.Message)
	}
	var indexes []string
	if err := resp.JSON(&indexes); err != nil {
		return nil, fmt.Errorf("failed to parse index list: %w", err)
	}
	return indexes, nil
}

// CollectionItemSet sets an item in a collection.
// If key is empty, the server will generate a unique ID.
func (c *Client) CollectionItemSet(collectionName, key string, value any, ttl time.Duration) (*CommandResponse, error) {
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value to JSON: %w", err)
	}

	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(key))
	payload.Write(writeBytes(valueBytes))
	binary.Write(&payload, byteOrder, int64(ttl.Seconds()))

	return c.sendCommand(cmdCollectionItemSet, payload.Bytes())
}

// CollectionItemSetMany sets multiple items in a collection.
func (c *Client) CollectionItemSetMany(collectionName string, items []any) (*CommandResponse, error) {
	itemsBytes, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal items to JSON: %w", err)
	}

	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeBytes(itemsBytes))

	return c.sendCommand(cmdCollectionItemSetMany, payload.Bytes())
}

// CollectionItemUpdate updates an item in a collection using a JSON patch.
func (c *Client) CollectionItemUpdate(collectionName, key string, patchValue any) (*CommandResponse, error) {
	patchBytes, err := json.Marshal(patchValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal patch value to JSON: %w", err)
	}

	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(key))
	payload.Write(writeBytes(patchBytes))

	return c.sendCommand(cmdCollectionItemUpdate, payload.Bytes())
}

// CollectionItemUpdateMany updates multiple items. Expects a slice of structs/maps, each with "_id" and "patch".
func (c *Client) CollectionItemUpdateMany(collectionName string, items []any) (*CommandResponse, error) {
	itemsBytes, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal items to JSON: %w", err)
	}

	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeBytes(itemsBytes))

	return c.sendCommand(cmdCollectionItemUpdateMany, payload.Bytes())
}

// CollectionItemGet gets an item from a collection by its key.
func (c *Client) CollectionItemGet(collectionName, key string) (*GetResult, error) {
	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(key))

	resp, err := c.sendCommand(cmdCollectionItemGet, payload.Bytes())
	if err != nil {
		return nil, err
	}
	return &GetResult{CommandResponse: resp}, nil
}

// CollectionItemDelete deletes an item from a collection by its key.
func (c *Client) CollectionItemDelete(collectionName, key string) (*CommandResponse, error) {
	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeString(key))
	return c.sendCommand(cmdCollectionItemDelete, payload.Bytes())
}

// CollectionItemDeleteMany deletes multiple items from a collection by their keys.
func (c *Client) CollectionItemDeleteMany(collectionName string, keys []string) (*CommandResponse, error) {
	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	binary.Write(&payload, byteOrder, uint32(len(keys)))
	for _, key := range keys {
		payload.Write(writeString(key))
	}
	return c.sendCommand(cmdCollectionItemDeleteMany, payload.Bytes())
}

// CollectionQuery performs a complex query on a collection.
func (c *Client) CollectionQuery(collectionName string, query Query) (*CommandResponse, error) {
	queryBytes, err := query.toJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to build query JSON: %w", err)
	}

	var payload bytes.Buffer
	payload.Write(writeString(collectionName))
	payload.Write(writeBytes(queryBytes))

	return c.sendCommand(cmdCollectionQuery, payload.Bytes())
}

// --- Internal Methods ---

func (c *Client) closeConnection() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.reader = nil
		c.writer = nil
		c.authenticatedUser = ""
		return err
	}
	return nil
}

func (c *Client) performAuthentication(username, password string) error {
	var payload bytes.Buffer
	payload.Write(writeString(username))
	payload.Write(writeString(password))

	c.writer.WriteByte(cmdAuthenticate)
	c.writer.Write(payload.Bytes())
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("auth flush failed: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode == statusOK {
		c.authenticatedUser = username
		return nil
	}

	return fmt.Errorf("authentication failed: %s: %s", resp.Status, resp.Message)
}

func (c *Client) sendCommand(commandType byte, payload []byte) (*CommandResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reconnect logic
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			// This call to Connect is already locked, so we call a stripped-down version
			return nil, fmt.Errorf("reconnection failed: %w", c.connectUnlocked())
		}
	}

	if commandType != cmdAuthenticate && c.authenticatedUser == "" {
		return nil, fmt.Errorf("client is not authenticated")
	}

	// First attempt
	resp, err := c.trySendCommand(commandType, payload)
	if err == nil {
		return resp, nil
	}

	// If it fails with a network error, try reconnecting and sending again once.
	if _, isNetErr := err.(net.Error); isNetErr || err == io.EOF || err == io.ErrUnexpectedEOF {
		fmt.Println("Connection lost, attempting to reconnect...")
		if reconnErr := c.connectUnlocked(); reconnErr != nil {
			return nil, fmt.Errorf("reconnection failed: %w", reconnErr)
		}
		// Second attempt
		return c.trySendCommand(commandType, payload)
	}

	return nil, err
}

// connectUnlocked is for use inside a locked context
func (c *Client) connectUnlocked() error {
	// ... (Same logic as Connect, but without locking)
	c.closeConnection() // Ensure clean state before connecting

	tlsConfig := &tls.Config{InsecureSkipVerify: c.insecure}
	if c.serverCertPath != "" {
		caCert, err := os.ReadFile(c.serverCertPath)
		if err != nil {
			return fmt.Errorf("failed to read server certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect via TLS: %w", err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)

	if c.username != "" && c.password != "" {
		return c.performAuthentication(c.username, c.password)
	}
	return nil
}

// trySendCommand performs a single attempt to send a command.
func (c *Client) trySendCommand(commandType byte, payload []byte) (*CommandResponse, error) {
	if c.writer == nil {
		return nil, io.EOF // Or another appropriate connection error
	}
	c.writer.WriteByte(commandType)
	c.writer.Write(payload)
	if err := c.writer.Flush(); err != nil {
		c.closeConnection()
		return nil, err
	}
	return c.readResponse()
}

func (c *Client) readResponse() (*CommandResponse, error) {
	status, err := c.reader.ReadByte()
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	msg, err := readString(c.reader)
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	data, err := readBytes(c.reader)
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	return &CommandResponse{
		StatusCode: status,
		Status:     getStatusString(status),
		Message:    msg,
		RawData:    data,
	}, nil
}

// --- Binary Protocol Helper Functions ---

func writeString(s string) []byte {
	sBytes := []byte(s)
	lenBytes := make([]byte, 4)
	byteOrder.PutUint32(lenBytes, uint32(len(sBytes)))
	return append(lenBytes, sBytes...)
}

func writeBytes(b []byte) []byte {
	lenBytes := make([]byte, 4)
	byteOrder.PutUint32(lenBytes, uint32(len(b)))
	return append(lenBytes, b...)
}

func readBytes(r io.Reader) ([]byte, error) {
	lenBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBytes); err != nil {
		return nil, err
	}
	length := byteOrder.Uint32(lenBytes)
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func readString(r io.Reader) (string, error) {
	data, err := readBytes(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
