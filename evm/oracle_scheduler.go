// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ══════════════════════════════════════════════════════════════════════
// Time Execution Engine — Scheduled Oracle Triggers
// Stores recurring oracle requests and executes them at the right block.
// ══════════════════════════════════════════════════════════════════════

// ScheduledTask represents a recurring execution request
type ScheduledTask struct {
	ID            [32]byte
	Caller        string
	FeedID        [32]byte
	Interval      uint64 // blocks between executions
	NextBlock     uint64 // next block to execute
	LastExecuted  uint64 // last block executed (0 = never)
	ExecutionCount uint64
	MaxExecutions uint64 // 0 = unlimited
	GasPrice      uint64
	Reward        uint64 // reward per execution
	Active        bool
}

// TimeExecution storage layout
const (
	teSlotTaskCount byte = 0x01
	teSlotTaskList  byte = 0x02
)

// TimeExecution manages scheduled tasks
type TimeExecution struct {
	Tasks     map[[32]byte]*ScheduledTask
	TaskOrder [][32]byte // insertion order for iteration
	State     *StateDB
}

// NewTimeExecution creates a new time execution engine
func NewTimeExecution(state *StateDB) *TimeExecution {
	return &TimeExecution{
		Tasks: make(map[[32]byte]*ScheduledTask),
		State: state,
	}
}

// ScheduleTask creates a new scheduled task
func (te *TimeExecution) ScheduleTask(caller string, feedID [32]byte, interval, startBlock uint64, maxExecutions uint64, reward uint64) ([32]byte, uint64, error) {
	if interval < 100 {
		return [32]byte{}, 0, fmt.Errorf("interval must be >= 100 blocks")
	}

	// Generate unique task ID
	idInput := fmt.Sprintf("%s:%x:%d:%d", caller, feedID, startBlock, te.getTaskCount()+1)
	taskID := sha256.Sum256([]byte(idInput))

	task := &ScheduledTask{
		ID:             taskID,
		Caller:         caller,
		FeedID:         feedID,
		Interval:       interval,
		NextBlock:      startBlock,
		LastExecuted:   0,
		ExecutionCount: 0,
		MaxExecutions:  maxExecutions,
		Reward:         reward,
		Active:         true,
	}

	te.Tasks[taskID] = task
	te.TaskOrder = append(te.TaskOrder, taskID)
	te.incrementTaskCount()

	return taskID, task.NextBlock, nil
}

// CancelTask deactivates a scheduled task
func (te *TimeExecution) CancelTask(taskID [32]byte, caller string) error {
	task, ok := te.Tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found")
	}
	if task.Caller != caller {
		return fmt.Errorf("only caller can cancel")
	}
	task.Active = false
	return nil
}

// ExecuteDueTasks runs all tasks that are due at the current block
// Returns the list of task IDs that were executed
func (te *TimeExecution) ExecuteDueTasks(blockNum uint64) ([][32]byte, []*ScheduledTask) {
	var executed [][32]byte
	var tasks []*ScheduledTask

	for _, taskID := range te.TaskOrder {
		task := te.Tasks[taskID]
		if !task.Active {
			continue
		}
		if task.MaxExecutions > 0 && task.ExecutionCount >= task.MaxExecutions {
			task.Active = false
			continue
		}
		if blockNum >= task.NextBlock {
			// Execute
			task.ExecutionCount++
			task.LastExecuted = blockNum
			task.NextBlock = blockNum + task.Interval
			executed = append(executed, taskID)
			tasks = append(tasks, task)

			// Pay reward to executor (caller)
			if task.Reward > 0 {
				acc := te.State.GetOrCreateAccount(task.Caller)
				acc.Balance.Add(acc.Balance, new(big.Int).SetUint64(task.Reward))
			}
		}
	}

	return executed, tasks
}

// GetTask returns a task by ID
func (te *TimeExecution) GetTask(taskID [32]byte) (*ScheduledTask, bool) {
	task, ok := te.Tasks[taskID]
	return task, ok
}

// GetActiveTasks returns all active tasks
func (te *TimeExecution) GetActiveTasks() []*ScheduledTask {
	var active []*ScheduledTask
	for _, taskID := range te.TaskOrder {
		task := te.Tasks[taskID]
		if task.Active {
			active = append(active, task)
		}
	}
	return active
}

// GetTasksDueAt returns tasks that will execute at a specific block
func (te *TimeExecution) GetTasksDueAt(blockNum uint64) []*ScheduledTask {
	var due []*ScheduledTask
	for _, taskID := range te.TaskOrder {
		task := te.Tasks[taskID]
		if task.Active && task.NextBlock == blockNum {
			due = append(due, task)
		}
	}
	return due
}

// getTaskCount returns current task count from storage
func (te *TimeExecution) getTaskCount() uint64 {
	addr := PrecompileAddrHex(0x0D)
	acc := te.State.GetOrCreateAccount(addr)
	key := storageKey([]byte{teSlotTaskCount})
	count := acc.Storage[key]
	if count == [32]byte{} {
		return 0
	}
	return new(big.Int).SetBytes(count[:]).Uint64()
}

// incrementTaskCount increments the task counter
func (te *TimeExecution) incrementTaskCount() {
	addr := PrecompileAddrHex(0x0D)
	acc := te.State.GetOrCreateAccount(addr)
	key := storageKey([]byte{teSlotTaskCount})
	count := te.getTaskCount() + 1
	var slot [32]byte
	new(big.Int).SetUint64(count).FillBytes(slot[:])
	acc.Storage[key] = slot
}

// PrintTaskSummary displays task info
func (task *ScheduledTask) PrintTaskSummary() {
	status := "ACTIVE"
	if !task.Active {
		status = "INACTIVE"
	}
	fmt.Printf("  Task %x: feed=%x interval=%d next=%d executed=%d [%s]\n",
		task.ID[:8], task.FeedID[:8], task.Interval, task.NextBlock, task.ExecutionCount, status)
}

// ══════════════════════════════════════════════════════════════════════
// Professional Oracle Badges — Earn income through verified profession
// ══════════════════════════════════════════════════════════════════════

// ProfessionalBadge stores verified professional credentials for oracle earnings
type ProfessionalBadge struct {
	Profession  string  // "geologist", "lawyer", "surveyor", "engineer"
	Verified    bool    // Dox_Dev badge + license verification
	RewardRate  uint64  // Reward per attestation (in WAY wei)
	TotalEarned uint64  // Lifetime earnings from professional attestations
}

// ProfessionalBadge storage slots (under TimeExecution precompile 0x0D)
const (
	pbSlotBadgeCount  byte = 0x10 // Total professional badges issued
	pbSlotBadgeList   byte = 0x11 // List of badge holders
	pbSlotProfession  byte = 0x12 // Profession string (hashed)
	pbSlotRewardRate  byte = 0x13 // Reward per attestation
	pbSlotTotalEarned byte = 0x14 // Lifetime earnings
	pbSlotApplication byte = 0x15 // Pending applications
	pbSlotVerification byte = 0x16 // Verification status
)

// ProfessionalBadge storage key helpers
func professionalBadgeKey(oracle string) [32]byte {
	return storageKey(append([]byte{pbSlotProfession}, []byte(oracle)...))
}

// profRewardKey returns reward rate storage key
func profRewardKey(oracle string) [32]byte {
	return storageKey(append([]byte{pbSlotRewardRate}, []byte(oracle)...))
}

// profEarnedKey returns total earned storage key
func profEarnedKey(oracle string) [32]byte {
	return storageKey(append([]byte{pbSlotTotalEarned}, []byte(oracle)...))
}

// profApplicationKey returns application storage key
func profApplicationKey(oracle, profession string) [32]byte {
	return storageKey(append(append([]byte{pbSlotApplication}, []byte(oracle)...), []byte(profession)...))
}

// CalculateProfessionalReward computes reward based on profession
// Geologist: 100 WAY wei per attestation
// Lawyer: 80 WAY wei per attestation
// Surveyor: 60 WAY wei per attestation
// Engineer: 70 WAY wei per attestation
func CalculateProfessionalReward(profession string, attestorAddress string) uint64 {
	rewardRates := map[string]uint64{
		"geologist": 100,
		"lawyer":    80,
		"surveyor":  60,
		"engineer":  70,
	}

	// Base reward for Level 2+ oracles
	rate, exists := rewardRates[profession]
	if !exists || rate == 0 {
		return 0
	}
	return rate
}

// ApplyForProfessionalBadge submits an application for a professional badge
// Requires Dox_Dev Level 2+ and valid profession
func ApplyForProfessionalBadge(profession string, licenseHash [32]byte, state *StateDB, caller string) error {
	// Validate profession
	validProfessions := map[string]bool{
		"geologist": true,
		"lawyer":    true,
		"surveyor":  true,
		"engineer":  true,
	}
	if !validProfessions[profession] {
		return fmt.Errorf("ProfessionalBadge: invalid profession %s", profession)
	}

	// Verify caller has Dox_Dev Level 2+
	acc := state.GetAccount(caller)
	if acc == nil || acc.DoxDevLevel < 2 {
		return fmt.Errorf("ProfessionalBadge: caller not verified (need Dox_Dev 2+)")
	}

	// Store application for curator review
	addr := PrecompileAddrHex(0x0D)
	precompileAcc := state.GetOrCreateAccount(addr)
	appKey := profApplicationKey(caller, profession)

	var appSlot [32]byte
	copy(appSlot[:], licenseHash[:])
	appSlot[31] = 1 // Application pending

	precompileAcc.Storage[appKey] = appSlot

	return nil
}

// VerifyProfessionalBadge marks a professional badge as verified
// Called by verified curators with Level 2+
func VerifyProfessionalBadge(profession string, state *StateDB, caller string) (bool, error) {
	// Verify caller is a curator
	addr := PrecompileAddrHex(0x13)
	badgeAcc := state.GetAccount(addr)
	if badgeAcc == nil {
		return false, fmt.Errorf("ProfessionalBadge: DoxDevBadge contract not found")
	}

	callerKey := storageKey(append([]byte{0x30}, []byte(caller)...))
	if readUint64(badgeAcc.Storage[callerKey]) == 0 {
		return false, fmt.Errorf("ProfessionalBadge: only curators can verify")
	}

	// Validate profession
	rewardRate := CalculateProfessionalReward(profession, caller)
	if rewardRate == 0 {
		return false, fmt.Errorf("ProfessionalBadge: invalid profession %s", profession)
	}

	// Mark as verified
	verificationKey := storageKey(append([]byte{pbSlotVerification}, []byte(caller)...))
	var verifySlot [32]byte
	// Store profession hash and mark verified
	profHash := sha256.Sum256([]byte(profession))
	copy(verifySlot[:], profHash[:])

	schedulerAddr := PrecompileAddrHex(0x0D)
	schedulerAcc := state.GetOrCreateAccount(schedulerAddr)
	schedulerAcc.Storage[verificationKey] = verifySlot

	// Set reward rate
	rewardKey := profRewardKey(caller)
	var rewardSlot [32]byte
	new(big.Int).SetUint64(rewardRate).FillBytes(rewardSlot[:])
	schedulerAcc.Storage[rewardKey] = rewardSlot

	return true, nil
}
