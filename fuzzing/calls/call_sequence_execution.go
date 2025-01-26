package calls

import (
	"fmt"
	"math/big"

	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/utils"
)

// ExecuteCallSequenceFetchElementFunc describes a function that is called to obtain the next call sequence element to
// execute. It is given the current call index in the sequence.
// Returns the call sequence element to execute, or an error if one occurs. If the call sequence element is nil,
// it indicates the end of the sequence and execution breaks.
type ExecuteCallSequenceFetchElementFunc func(index int) (*CallSequenceElement, error)

// ExecuteCallSequenceExecutionCheckFunc describes a function that is called after each call is executed in a
// sequence. It is given the currently executed call sequence to this point.
// Returns a boolean indicating if the sequence execution should break, or an error if one occurs.
type ExecuteCallSequenceExecutionCheckFunc func(currentExecutedSequence CallSequence) (bool, error)

// ExecuteCallSequenceIteratively executes a CallSequence upon a provided chain iteratively. It ensures calls are
// included in blocks which adhere to the CallSequence properties (such as delays) as much as possible.
// A "fetch next call" function is provided to fetch the next element to execute.
// A "post element executed check" function is provided to check whether execution should stop after each element is
// executed.
// Returns the call sequence which was executed and an error if one occurs.
func ExecuteCallSequenceIteratively(chain *chain.TestChain, fetchElementFunc ExecuteCallSequenceFetchElementFunc, executionCheckFunc ExecuteCallSequenceExecutionCheckFunc, additionalTracers ...*chain.TestChainTracer) (CallSequence, error) {
	// If there is no fetch element function provided, throw an error
	if fetchElementFunc == nil {
		return nil, fmt.Errorf("could not execute call sequence on chain as the 'fetch element function' provided was nil")
	}

	// Create a call sequence to track all elements executed throughout this operation.
	var callSequenceExecuted CallSequence

	// Create a variable to track if the post-execution check operation requested we break execution.
	execCheckFuncRequestedBreak := false

	// Loop through each sequence element in our sequence we'll want to execute.
	for i := 0; true; i++ {
		// Call our "fetch next call" function and obtain our next call sequence element.
		callSequenceElement, err := fetchElementFunc(i)
		if err != nil {
			return callSequenceExecuted, err
		}

		// If we are at the end of our sequence, break out of our execution loop.
		if callSequenceElement == nil {
			break
		}

		// Process contract setup hook if present
		err = executeContractSetupHook(chain, callSequenceElement, &callSequenceExecuted)
		if err != nil {
			return callSequenceExecuted, err
		}

		// Add transaction to pending block
		err = addTxToPendingBlock(chain, callSequenceElement.BlockNumberDelay, callSequenceElement.BlockTimestampDelay, callSequenceElement.Call, additionalTracers...)
		if err != nil {
			return callSequenceExecuted, err
		}

		// Update our chain reference for this element.
		callSequenceElement.ChainReference = &CallSequenceElementChainReference{
			Block:            chain.PendingBlock(),
			TransactionIndex: len(chain.PendingBlock().Messages) - 1,
		}

		// Add to our executed call sequence
		callSequenceExecuted = append(callSequenceExecuted, callSequenceElement)

		// We added our call to the block as a transaction. Call our step function with the update and check
		// if it returned an error.
		if executionCheckFunc != nil {
			execCheckFuncRequestedBreak, err = executionCheckFunc(callSequenceExecuted)
			if err != nil {
				return callSequenceExecuted, err
			}

			// If post-execution check requested we break execution, break out of our "retry loop"
			if execCheckFuncRequestedBreak {
				break
			}
		}

		// We didn't encounter an error, so we were successful in adding this transaction. Break out of this
		// inner "retry loop" and move onto processing the next element in the outer loop.
		break
	}

	// Commit the last pending block.
	if chain.PendingBlock() != nil {
		err := chain.PendingBlockCommit()
		if err != nil {
			return callSequenceExecuted, err
		}
	}
	return callSequenceExecuted, nil
}

// ExecuteCallSequence executes a provided CallSequence on the provided chain.
// It returns the slice of the call sequence which was tested, and an error if one occurred.
// If no error occurred, it can be expected that the returned call sequence contains all elements originally provided.
func ExecuteCallSequence(chain *chain.TestChain, callSequence CallSequence) (CallSequence, error) {
	// Execute our sequence with a simple fetch operation provided to obtain each element.
	fetchElementFunc := func(currentIndex int) (*CallSequenceElement, error) {
		if currentIndex < len(callSequence) {
			return callSequence[currentIndex], nil
		}
		return nil, nil
	}

	return ExecuteCallSequenceIteratively(chain, fetchElementFunc, nil)
}

// ExecuteCallSequenceWithExecutionTracer attaches an executiontracer.ExecutionTracer to ExecuteCallSequenceIteratively and attaches execution traces to the call sequence elements.
func ExecuteCallSequenceWithExecutionTracer(testChain *chain.TestChain, contractDefinitions contracts.Contracts, callSequence CallSequence, verboseTracing bool) (CallSequence, error) {
	// Create a new execution tracer
	executionTracer := executiontracer.NewExecutionTracer(contractDefinitions, testChain.CheatCodeContracts())
	defer executionTracer.Close()

	// Execute our sequence with a simple fetch operation provided to obtain each element.
	fetchElementFunc := func(currentIndex int) (*CallSequenceElement, error) {
		if currentIndex < len(callSequence) {
			return callSequence[currentIndex], nil
		}
		return nil, nil
	}

	// Execute the call sequence and attach the execution tracer
	executedCallSeq, err := ExecuteCallSequenceIteratively(testChain, fetchElementFunc, nil, executionTracer.NativeTracer())

	// By default, we only trace the last element in the call sequence.
	traceFrom := len(callSequence) - 1
	// If verbose tracing is enabled, we want to trace all elements in the call sequence.
	if verboseTracing {
		traceFrom = 0
	}

	// Attach the execution trace for each requested call sequence element
	for ; traceFrom < len(callSequence); traceFrom++ {
		callSequenceElement := callSequence[traceFrom]
		hash := utils.MessageToTransaction(callSequenceElement.Call.ToCoreMessage()).Hash()
		callSequenceElement.ExecutionTrace = executionTracer.GetTrace(hash)
	}

	return executedCallSeq, err
}

// executeContractSetupHook processes the contract setup hook for the call sequence element, if exists.
func executeContractSetupHook(chain *chain.TestChain, callSequenceElement *CallSequenceElement, callSequenceExecuted *CallSequence) error {
	if callSequenceElement.Contract == nil || callSequenceElement.Contract.SetupHook == nil {
		return nil
	}

	// Get contract setup hook
	contractSetupHook := callSequenceElement.Contract.SetupHook

	// Create a call targeting contract setup hook
	msg := NewCallMessageWithAbiValueData(contractSetupHook.DeployerAddress, callSequenceElement.Call.To, 0, big.NewInt(0), callSequenceElement.Call.GasLimit, nil, nil, nil, &CallMessageDataAbiValues{
		Method:      contractSetupHook.Method,
		InputValues: nil,
	})

	// Execute the call
	// If we have no pending block to add a tx containing our call to, we must create one.
	err := addTxToPendingBlock(chain, callSequenceElement.BlockNumberDelay, callSequenceElement.BlockTimestampDelay, msg)
	if err != nil {
		return err
	}

	setupCallSequenceElement := NewCallSequenceElement(callSequenceElement.Contract, msg, callSequenceElement.BlockNumberDelay, callSequenceElement.BlockTimestampDelay)
	setupCallSequenceElement.ChainReference = &CallSequenceElementChainReference{
		Block:            chain.PendingBlock(),
		TransactionIndex: len(chain.PendingBlock().Messages) - 1,
	}

	// Register the call in our call sequence so it gets registered in coverage.
	*callSequenceExecuted = append(*callSequenceExecuted, setupCallSequenceElement)
	return nil
}

// addTxToPendingBlock ensures a transaction is added to a pending block, creating a new block if necessary.
// It handles block delays and retries if the block is full.
func addTxToPendingBlock(chain *chain.TestChain, blockNumberDelay uint64, blockTimestampDelay uint64, msg *CallMessage, additionalTracers ...*chain.TestChainTracer) error {
	for {
		msg.FillFromTestChainProperties(chain)

		// If we have a pending block, but we intend to delay this call from the last, we commit that block.
		if chain.PendingBlock() != nil && blockNumberDelay > 0 {
			err := chain.PendingBlockCommit()
			if err != nil {
				return err
			}
		}

		// If we have no pending block to add a tx containing our call to, we must create one.
		if chain.PendingBlock() == nil {
			// The minimum step between blocks must be 1 in block number and timestamp, so we ensure this is the case.
			numberDelay := blockNumberDelay
			timeDelay := blockTimestampDelay
			if numberDelay == 0 {
				numberDelay = 1
			}
			if timeDelay == 0 {
				timeDelay = 1
			}

			// Each timestamp/block number must be unique as well, so we cannot jump more block numbers than time.
			if numberDelay > timeDelay {
				numberDelay = timeDelay
			}
			_, err := chain.PendingBlockCreateWithParameters(chain.Head().Header.Number.Uint64()+numberDelay, chain.Head().Header.Time+timeDelay, nil)
			if err != nil {
				return err
			}
		}

		// Try to add our transaction to this block.
		err := chain.PendingBlockAddTx(msg.ToCoreMessage(), additionalTracers...)

		if err != nil {
			// If we encountered a block gas limit error and there are other transactions in the block,
			// commit the pending block and try again in a new block.
			if len(chain.PendingBlock().Messages) > 0 {
				err := chain.PendingBlockCommit()
				if err != nil {
					return err
				}
				continue
			}
			// If there are no transactions in our block, and we failed to add this one, return the error
			return err
		}

		return nil
	}
}
