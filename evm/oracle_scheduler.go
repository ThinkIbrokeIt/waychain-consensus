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
