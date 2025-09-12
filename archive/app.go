package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/dgraph-io/badger/v4"
)

type Action string

const (
	Add Action = "ADD"
	Mod Action = "MOD"
	Del Action = "DEL"
)

type Message struct {
	Host   string `json:"host"`
	Action Action `json:"action"`
}

type EvaluatedEntry struct {
	Action     Action    `json:"action"`
	Timestamp  time.Time `json:"timestamp"`
	PolicyHash string    `json:"policy_hash"`
}

type WebcatApplication struct {
	db           *badger.DB
	onGoingBlock *badger.Txn
}

var _ abcitypes.Application = (*WebcatApplication)(nil)

func (app *WebcatApplication) isValid(tx []byte) uint32 {
	var jsonTx Message
	if err := json.Unmarshal(tx, &jsonTx); err != nil {
		return 1
	}

	if jsonTx.Host == "" || jsonTx.Action == "" {
		return 1
	}

	normalizedHost, err := normalizeHostname(jsonTx.Host)
	if err != nil || normalizedHost != jsonTx.Host {
		return 1
	}

	switch jsonTx.Action {
	case Add, Mod, Del:
		// ok
	default:
		return 1
	}

	return 0
}

func (app *WebcatApplication) FinalizeBlock(_ context.Context, req *abcitypes.FinalizeBlockRequest) (*abcitypes.FinalizeBlockResponse, error) {
	processed := make(map[string]bool)
	txs := make([]*abcitypes.ExecTxResult, len(req.Txs))
	app.onGoingBlock = app.db.NewTransaction(true)

	for i, tx := range req.Txs {
		if code := app.isValid(tx); code != 0 {
			log.Printf("Invalid transaction at index %v", i)
			txs[i] = &abcitypes.ExecTxResult{Code: code}
			continue
		}

		// Check for duplicate host within the block
		var jsonTx Message
		_ = json.Unmarshal(tx, &jsonTx)

		if processed[jsonTx.Host] {
			txs[i] = &abcitypes.ExecTxResult{Code: 1, Log: "duplicate host action in same block"}
			continue
		}
		processed[jsonTx.Host] = true

		log.Printf("Evaluating %s for host %s", jsonTx.Action, jsonTx.Host)

		policyHash, err := fetchPolicyHash(jsonTx.Host)
		if err != nil {
			log.Printf("Failed to fetch policy for host %s: %v", jsonTx.Host, err)
			txs[i] = &abcitypes.ExecTxResult{Code: 1, Log: "policy fetch failed"}
			continue
		}

		key := []byte(jsonTx.Host)
		existingHash := ""
		app.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(key)
			if err == nil {
				_ = item.Value(func(v []byte) error {
					var prev EvaluatedEntry
					if err := json.Unmarshal(v, &prev); err == nil {
						existingHash = prev.PolicyHash
					}
					return nil
				})
			}
			return nil
		})

		// Validate transitions
		if jsonTx.Action == Add && existingHash != "" {
			txs[i] = &abcitypes.ExecTxResult{Code: 1, Log: "host already exists"}
			continue
		}
		if jsonTx.Action == Mod && (existingHash == "" || existingHash == policyHash) {
			txs[i] = &abcitypes.ExecTxResult{Code: 1, Log: "invalid modify"}
			continue
		}
		if jsonTx.Action == Del && existingHash == "" {
			txs[i] = &abcitypes.ExecTxResult{Code: 1, Log: "cannot delete missing host"}
			continue
		}

		if jsonTx.Action == Del {
			if err := app.onGoingBlock.Delete(key); err != nil {
				log.Panicf("delete failed: %v", err)
			}
		} else {
			entry := EvaluatedEntry{
				Action:     jsonTx.Action,
				Timestamp:  req.Time,
				PolicyHash: policyHash,
			}
			val, _ := json.Marshal(entry)
			if err := app.onGoingBlock.Set(key, val); err != nil {
				log.Panicf("write failed: %v", err)
			}
		}

		txs[i] = &abcitypes.ExecTxResult{
			Code: 0,
			Events: []abcitypes.Event{{
				Type: "webcat",
				Attributes: []abcitypes.EventAttribute{
					{Key: "host", Value: jsonTx.Host, Index: true},
				},
			}},
		}
	}

	return &abcitypes.FinalizeBlockResponse{TxResults: txs}, nil
}

func NewWebcatApplication(db *badger.DB) *WebcatApplication {
	return &WebcatApplication{db: db}
}

var _ abcitypes.Application = (*WebcatApplication)(nil)

func (app *WebcatApplication) Info(_ context.Context, info *abcitypes.InfoRequest) (*abcitypes.InfoResponse, error) {
	return &abcitypes.InfoResponse{}, nil
}

func (app *WebcatApplication) Query(_ context.Context, req *abcitypes.QueryRequest) (*abcitypes.QueryResponse, error) {
	resp := abcitypes.QueryResponse{Key: req.Data}

	dbErr := app.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(req.Data)
		if err != nil {
			if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
			resp.Log = "key does not exist"
			return nil
		}

		return item.Value(func(val []byte) error {
			resp.Log = "exists"
			resp.Value = val
			return nil
		})
	})
	if dbErr != nil {
		log.Panicf("Error reading database, unable to execute query: %v", dbErr)
	}
	return &resp, nil
}

func (app *WebcatApplication) CheckTx(_ context.Context, check *abcitypes.CheckTxRequest) (*abcitypes.CheckTxResponse, error) {
	code := app.isValid(check.Tx)
	return &abcitypes.CheckTxResponse{Code: code}, nil
}

func (app *WebcatApplication) InitChain(_ context.Context, chain *abcitypes.InitChainRequest) (*abcitypes.InitChainResponse, error) {
	return &abcitypes.InitChainResponse{}, nil
}

func (app *WebcatApplication) PrepareProposal(_ context.Context, proposal *abcitypes.PrepareProposalRequest) (*abcitypes.PrepareProposalResponse, error) {
	return &abcitypes.PrepareProposalResponse{Txs: proposal.Txs}, nil
}

func (app *WebcatApplication) ProcessProposal(_ context.Context, proposal *abcitypes.ProcessProposalRequest) (*abcitypes.ProcessProposalResponse, error) {
	return &abcitypes.ProcessProposalResponse{Status: abcitypes.PROCESS_PROPOSAL_STATUS_ACCEPT}, nil
}

func (app WebcatApplication) Commit(_ context.Context, commit *abcitypes.CommitRequest) (*abcitypes.CommitResponse, error) {
	return &abcitypes.CommitResponse{}, app.onGoingBlock.Commit()
}

func (app *WebcatApplication) ListSnapshots(_ context.Context, snapshots *abcitypes.ListSnapshotsRequest) (*abcitypes.ListSnapshotsResponse, error) {
	return &abcitypes.ListSnapshotsResponse{}, nil
}

func (app *WebcatApplication) OfferSnapshot(_ context.Context, snapshot *abcitypes.OfferSnapshotRequest) (*abcitypes.OfferSnapshotResponse, error) {
	return &abcitypes.OfferSnapshotResponse{}, nil
}

func (app *WebcatApplication) LoadSnapshotChunk(_ context.Context, chunk *abcitypes.LoadSnapshotChunkRequest) (*abcitypes.LoadSnapshotChunkResponse, error) {
	return &abcitypes.LoadSnapshotChunkResponse{}, nil
}

func (app *WebcatApplication) ApplySnapshotChunk(_ context.Context, chunk *abcitypes.ApplySnapshotChunkRequest) (*abcitypes.ApplySnapshotChunkResponse, error) {
	return &abcitypes.ApplySnapshotChunkResponse{Result: abcitypes.APPLY_SNAPSHOT_CHUNK_RESULT_ACCEPT}, nil
}

func (app WebcatApplication) ExtendVote(_ context.Context, extend *abcitypes.ExtendVoteRequest) (*abcitypes.ExtendVoteResponse, error) {
	return &abcitypes.ExtendVoteResponse{}, nil
}

func (app *WebcatApplication) VerifyVoteExtension(_ context.Context, verify *abcitypes.VerifyVoteExtensionRequest) (*abcitypes.VerifyVoteExtensionResponse, error) {
	return &abcitypes.VerifyVoteExtensionResponse{}, nil
}
