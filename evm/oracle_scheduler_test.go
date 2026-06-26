package evm

import (
	"testing"
)

func TestTimeExecutionScheduleTask(t *testing.T) {
	state := NewStateDB()

	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("ethereum-price-feed-abcd"))

	taskID, nextBlock, err := te.ScheduleTask("0xAlice", feedID, 500, 10000, 0, 1000)
	if err != nil {
		t.Fatalf("ScheduleTask failed: %v", err)
	}
	if nextBlock != 10000 {
		t.Fatalf("expected nextBlock=10000, got %d", nextBlock)
	}
	if taskID == [32]byte{} {
		t.Fatal("taskID should not be zero")
	}

	// Verify task stored
	task, ok := te.GetTask(taskID)
	if !ok {
		t.Fatal("task should exist")
	}
	if task.Interval != 500 {
		t.Fatalf("expected interval=500, got %d", task.Interval)
	}
	if task.NextBlock != 10000 {
		t.Fatalf("expected NextBlock=10000, got %d", task.NextBlock)
	}
	if !task.Active {
		t.Fatal("task should be active")
	}

	_ = feedID
}

func TestTimeExecutionIntervalTooShort(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	_, _, err := te.ScheduleTask("0xAlice", feedID, 50, 1000, 0, 0)
	if err == nil {
		t.Fatal("expected error for interval < 100")
	}
}

func TestTimeExecutionStartBlockInPast(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	// ScheduleTask doesn't clamp startBlock — the precompile wrapper does
	// So startBlock=500 with blockNum=0 should keep startBlock=500
	_, nextBlock, err := te.ScheduleTask("0xAlice", feedID, 200, 500, 0, 0)
	if err != nil {
		t.Fatalf("ScheduleTask failed: %v", err)
	}
	// ScheduleTask stores startBlock as-is; clamping happens in precompile
	if nextBlock != 500 {
		t.Fatalf("expected nextBlock=500, got %d", nextBlock)
	}
}

func TestTimeExecutionExecuteDueTasks(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("test-feed"))
	te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)

	// Block 1 — not due yet (nextBlock=100)
	executed, _ := te.ExecuteDueTasks(1)
	if len(executed) != 0 {
		t.Fatalf("should not execute at block 1, got %d executions", len(executed))
	}

	// Block 100 — due
	executed, tasks := te.ExecuteDueTasks(100)
	if len(executed) != 1 {
		t.Fatalf("should execute 1 task at block 100, got %d", len(executed))
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task pointer, got %d", len(tasks))
	}
	if tasks[0].ExecutionCount != 1 {
		t.Fatalf("expected execution count=1, got %d", tasks[0].ExecutionCount)
	}
	if tasks[0].NextBlock != 200 {
		t.Fatalf("expected nextBlock=200 after execution, got %d", tasks[0].NextBlock)
	}
}

func TestTimeExecutionRecurringTask(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("test-feed"))
	te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)

	// Execute at blocks 100, 200, 300
	for block := uint64(100); block <= 300; block += 100 {
		executed, _ := te.ExecuteDueTasks(block)
		if len(executed) != 1 {
			t.Fatalf("block %d: expected 1 execution, got %d", block, len(executed))
		}
	}

	// 4th execution at 400 should also work
	executed, _ := te.ExecuteDueTasks(400)
	if len(executed) != 1 {
		t.Fatalf("block 400: expected 1 execution, got %d", len(executed))
	}

	tasks := te.GetActiveTasks()
	if len(tasks) != 1 {
		t.Fatalf("expected 1 active task, got %d", len(tasks))
	}
}

func TestTimeExecutionMaxExecutions(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("test-feed-max"))
	te.ScheduleTask("0xAlice", feedID, 100, 100, 2, 0) // max 2 executions

	te.ExecuteDueTasks(100) // 1st
	te.ExecuteDueTasks(200) // 2nd

	// 3rd should not execute (max reached)
	executed, _ := te.ExecuteDueTasks(300)
	if len(executed) != 0 {
		t.Fatalf("should not execute after max executions, got %d", len(executed))
	}
}

func TestTimeExecutionCancelTask(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("cancel-test"))
	taskID, _, _ := te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)

	// Cancel
	err := te.CancelTask(taskID, "0xAlice")
	if err != nil {
		t.Fatalf("CancelTask failed: %v", err)
	}

	// Should not execute
	executed, _ := te.ExecuteDueTasks(100)
	if len(executed) != 0 {
		t.Fatal("cancelled task should not execute")
	}
}

func TestTimeExecutionCancelUnauthorized(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	taskID, _, _ := te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)

	// Bob tries to cancel Alice's task
	err := te.CancelTask(taskID, "0xBob")
	if err == nil {
		t.Fatal("expected error: only caller can cancel")
	}
}

func TestTimeExecutionGetTasksDueAt(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID1, feedID2 [32]byte
	copy(feedID1[:], []byte("feed-1"))
	copy(feedID2[:], []byte("feed-2"))
	te.ScheduleTask("0xAlice", feedID1, 100, 200, 0, 0)
	te.ScheduleTask("0xBob", feedID2, 100, 200, 0, 0)

	due := te.GetTasksDueAt(200)
	if len(due) != 2 {
		t.Fatalf("expected 2 tasks due at block 200, got %d", len(due))
	}

	due = te.GetTasksDueAt(199)
	if len(due) != 0 {
		t.Fatalf("expected 0 tasks due at block 199, got %d", len(due))
	}
}

func TestTimeExecutionReward(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("reward-test"))
	te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 500) // 500 reward per execution

	acc := state.GetOrCreateAccount("0xAlice")
	initialBalance := acc.Balance.Uint64()

	te.ExecuteDueTasks(100)

	acc = state.GetOrCreateAccount("0xAlice")
	expected := initialBalance + 500
	if acc.Balance.Uint64() != expected {
		t.Fatalf("expected balance %d, got %d", expected, acc.Balance.Uint64())
	}
}

func TestTimeExecutionMultipleTasks(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID1, feedID2, feedID3 [32]byte
	copy(feedID1[:], []byte("feed-a"))
	copy(feedID2[:], []byte("feed-b"))
	copy(feedID3[:], []byte("feed-c"))
	te.ScheduleTask("0xAlice", feedID1, 100, 100, 0, 0)
	te.ScheduleTask("0xBob", feedID2, 100, 100, 0, 0)
	te.ScheduleTask("0xCharlie", feedID3, 200, 100, 0, 0)

	// Verify all 3 registered
	t.Logf("Tasks map: %d entries", len(te.Tasks))
	t.Logf("TaskOrder: %d entries", len(te.TaskOrder))
	for i, id := range te.TaskOrder {
		t.Logf("  task[%d]: %x", i, id[:8])
	}

	// Block 100: all three due
	executed, _ := te.ExecuteDueTasks(100)
	if len(executed) != 3 {
		t.Fatalf("block 100: expected 3 executions, got %d", len(executed))
	}

	// Block 200: Alice and Bob due (100-block intervals)
	executed, _ = te.ExecuteDueTasks(200)
	if len(executed) != 2 {
		t.Fatalf("block 200: expected 2 executions, got %d", len(executed))
	}
}

func TestTimeExecutionTaskCount(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("count-test"))

	if te.getTaskCount() != 0 {
		t.Fatalf("initial count should be 0, got %d", te.getTaskCount())
	}

	te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)
	if te.getTaskCount() != 1 {
		t.Fatalf("count should be 1, got %d", te.getTaskCount())
	}

	te.ScheduleTask("0xBob", feedID, 200, 200, 0, 0)
	if te.getTaskCount() != 2 {
		t.Fatalf("count should be 2, got %d", te.getTaskCount())
	}
}

func TestTimeExecutionActiveTasks(t *testing.T) {
	state := NewStateDB()
	te := NewTimeExecution(state)

	var feedID [32]byte
	copy(feedID[:], []byte("active-test"))
	te.ScheduleTask("0xAlice", feedID, 100, 100, 0, 0)
	te.ScheduleTask("0xBob", feedID, 100, 100, 0, 0)

	if len(te.GetActiveTasks()) != 2 {
		t.Fatalf("expected 2 active tasks, got %d", len(te.GetActiveTasks()))
	}

	// Cancel one
	taskID, _, _ := te.ScheduleTask("0xCharlie", feedID, 100, 100, 0, 0)
	te.CancelTask(taskID, "0xCharlie")

	if len(te.GetActiveTasks()) != 2 {
		t.Fatalf("expected 2 active tasks after cancel, got %d", len(te.GetActiveTasks()))
	}
}
