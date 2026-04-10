// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cluster

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RaftState represents the Raft consensus state of a node
type RaftState string

const (
	RaftStateFollower  RaftState = "follower"
	RaftStateCandidate RaftState = "candidate"
	RaftStateLeader    RaftState = "leader"
	RaftStateShutdown  RaftState = "shutdown"
	RaftStateUnknown   RaftState = "unknown"
)

// NodeState represents the health state of a node
type NodeState string

const (
	NodeStateAlive   NodeState = "alive"
	NodeStateSuspect NodeState = "suspect"
	NodeStateDead    NodeState = "dead"
	NodeStateLeft    NodeState = "left"
	NodeStateUnknown NodeState = "unknown"
)

// formatTimestamp formats a time.Time for display
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.UTC().Format(time.RFC3339)
}

// formatDuration formats a duration for human-readable display
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "N/A"
	}

	days := int64(d.Hours()) / 24
	hours := int64(d.Hours()) % 24
	minutes := int64(d.Minutes()) % 60
	seconds := int64(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, "")
}

// formatUptime formats an uptime duration for display
func formatUptime(startTime time.Time) string {
	if startTime.IsZero() {
		return "N/A"
	}
	return formatDuration(time.Since(startTime))
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatRaftState formats a Raft state for display
func formatRaftState(state RaftState) string {
	switch state {
	case RaftStateLeader:
		return "LEADER"
	case RaftStateFollower:
		return "FOLLOWER"
	case RaftStateCandidate:
		return "CANDIDATE"
	case RaftStateShutdown:
		return "SHUTDOWN"
	default:
		return "UNKNOWN"
	}
}

// formatNodeState formats a node state for display
func formatNodeState(state NodeState) string {
	switch state {
	case NodeStateAlive:
		return "ALIVE"
	case NodeStateSuspect:
		return "SUSPECT"
	case NodeStateDead:
		return "DEAD"
	case NodeStateLeft:
		return "LEFT"
	default:
		return "UNKNOWN"
	}
}

// formatTerm formats a Raft term for display
func formatTerm(term uint64) string {
	return fmt.Sprintf("%d", term)
}

// formatCommitIndex formats a Raft commit index for display
func formatCommitIndex(index uint64) string {
	return fmt.Sprintf("%d", index)
}

// parseAddressList parses a comma-separated list of addresses
func parseAddressList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// validateAddress validates an address format (host:port)
func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be in host:port format")
	}
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}
	return nil
}

// validateAddressList validates a list of addresses
func validateAddressList(addrs []string) error {
	for _, addr := range addrs {
		if err := validateAddress(addr); err != nil {
			return ErrInvalidJoinAddr{Addr: addr, Reason: err.Error()}
		}
	}
	return nil
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// truncateID truncates a node ID for display
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}

// ClusterStatusSummary is a cluster status representation for JSON/YAML output
type ClusterStatusSummary struct {
	ClusterID    string `json:"cluster_id" yaml:"cluster_id"`
	NodeID       string `json:"node_id" yaml:"node_id"`
	RaftState    string `json:"raft_state" yaml:"raft_state"`
	LeaderID     string `json:"leader_id" yaml:"leader_id"`
	LeaderAddr   string `json:"leader_addr" yaml:"leader_addr"`
	Term         uint64 `json:"term" yaml:"term"`
	CommitIndex  uint64 `json:"commit_index" yaml:"commit_index"`
	AppliedIndex uint64 `json:"applied_index" yaml:"applied_index"`
	LastContact  string `json:"last_contact" yaml:"last_contact"`
	NodeCount    int    `json:"node_count" yaml:"node_count"`
	VoterCount   int    `json:"voter_count" yaml:"voter_count"`
	Healthy      bool   `json:"healthy" yaml:"healthy"`
	Timestamp    string `json:"timestamp" yaml:"timestamp"`
}

// NodeInfo represents a cluster node for JSON/YAML output
type NodeInfo struct {
	NodeID    string `json:"node_id" yaml:"node_id"`
	Address   string `json:"address" yaml:"address"`
	State     string `json:"state" yaml:"state"`
	RaftState string `json:"raft_state" yaml:"raft_state"`
	IsVoter   bool   `json:"is_voter" yaml:"is_voter"`
	IsLeader  bool   `json:"is_leader" yaml:"is_leader"`
	LastSeen  string `json:"last_seen" yaml:"last_seen"`
	Uptime    string `json:"uptime" yaml:"uptime"`
}

// NodeListResponse represents the node list response
type NodeListResponse struct {
	Nodes      []*NodeInfo `json:"nodes" yaml:"nodes"`
	TotalCount int         `json:"total_count" yaml:"total_count"`
	VoterCount int         `json:"voter_count" yaml:"voter_count"`
	LeaderID   string      `json:"leader_id" yaml:"leader_id"`
}

// BootstrapResult represents the result of a bootstrap operation
type BootstrapResult struct {
	ClusterID  string `json:"cluster_id" yaml:"cluster_id"`
	NodeID     string `json:"node_id" yaml:"node_id"`
	ListenAddr string `json:"listen_addr" yaml:"listen_addr"`
	DataDir    string `json:"data_dir" yaml:"data_dir"`
	Success    bool   `json:"success" yaml:"success"`
	Message    string `json:"message" yaml:"message"`
}

// JoinResult represents the result of a join operation
type JoinResult struct {
	NodeID     string   `json:"node_id" yaml:"node_id"`
	ClusterID  string   `json:"cluster_id" yaml:"cluster_id"`
	LeaderID   string   `json:"leader_id" yaml:"leader_id"`
	LeaderAddr string   `json:"leader_addr" yaml:"leader_addr"`
	JoinedFrom []string `json:"joined_from" yaml:"joined_from"`
	Success    bool     `json:"success" yaml:"success"`
	Message    string   `json:"message" yaml:"message"`
}

// LeaveResult represents the result of a leave operation
type LeaveResult struct {
	NodeID  string `json:"node_id" yaml:"node_id"`
	Force   bool   `json:"force" yaml:"force"`
	Success bool   `json:"success" yaml:"success"`
	Message string `json:"message" yaml:"message"`
}
