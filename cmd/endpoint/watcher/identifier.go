package watcher

import (
	"math/big"
	"strings"

	"github.com/icon-project/icon-bridge/cmd/endpoint/chainAPI"
	"github.com/icon-project/icon-bridge/cmd/endpoint/chainAPI/chain"
	ctr "github.com/icon-project/icon-bridge/cmd/endpoint/decoder/contracts"
	"github.com/icon-project/icon-bridge/cmd/endpoint/decoder/contracts/nativeIcon"
	"github.com/icon-project/icon-bridge/cmd/endpoint/decoder/contracts/tokenIcon"
)

// If txn and txr matches a condition, spawn and instance of an identifier
// This identifier object will check the eventLog for a matching criteria
// So, for a single transaction there can be multiple identifiers
// All of these identifiers will send to a single channel
// This single channel will act as sink for multiple identifiers of a single txn
// A test unit can have multiple such txns: all results should be sent to that single channel
// Identifier Group maps inputCriterion to an instance of txn

type eventLogInfo struct {
	sourceChain  chain.ChainType
	contractName ctr.ContractName
	eventType    string
	eventLog     interface{}
}

type args struct {
	req     *chainAPI.RequestParam
	initRes interface{}
}

type identifierGroup struct {
	name        string
	description string
	req         *chainAPI.RequestParam
	init        func(txn *chainAPI.RequestParam) bool
	initRes     interface{}
	idfs        []identifier
}

type identifier struct {
	preRun func(args args, info eventLogInfo) bool
	run    func(args args, info eventLogInfo) bool
}

var DefaultIdentifierGroup = []identifierGroup{
	{
		name:        "InterChainI2H",
		description: "Transactions from icon to hmny chain for all tokens",
		init: func(req *chainAPI.RequestParam) bool {
			if req.FromChain == chain.ICON && req.ToChain == chain.HMNY {
				return true
			}
			return false
		},
		idfs: []identifier{ // all identifiers should match
			{ // identifier for TransferStart for all tokens
				preRun: func(args args, info eventLogInfo) bool { // TransferStart msg on icon chain
					if info.sourceChain == chain.ICON && info.eventType == "TransferStart" &&
						(info.contractName == ctr.NativeIcon || info.contractName == ctr.TokenIcon) {
						return true
					}
					return false
				},
				run: func(args args, info eventLogInfo) bool {
					if info.contractName == ctr.NativeIcon {
						if el, ok := info.eventLog.(*nativeIcon.NativeIconTransferStart); ok {
							splts := strings.Split(el.To, "/")
							seq := args.initRes.(*big.Int)
							if el.From == args.req.FromAddress && args.req.ToAddress == splts[len(splts)-1] && el.Sn == seq {
								return true
							}
						}
					} else if info.contractName == ctr.TokenIcon {
						if el, ok := info.eventLog.(*tokenIcon.TokenIconTransferStart); ok {
							splts := strings.Split(el.To, "/")
							seq := args.initRes.(*big.Int)
							if el.From == args.req.FromAddress && args.req.ToAddress == splts[len(splts)-1] && el.Sn == seq {
								return true
							}
						}
					}
					return false
				},
			},
			{
				preRun: func(args args, info eventLogInfo) bool { // TransferStart msg on icon chain
					if info.sourceChain == chain.ICON && info.eventType == "TransferEnd" &&
						(info.contractName == ctr.NativeIcon || info.contractName == ctr.TokenIcon) {
						return true
					}
					return false
				},
				run: func(args args, info eventLogInfo) bool {
					if info.contractName == ctr.NativeIcon {
						if el, ok := info.eventLog.(*nativeIcon.NativeIconTransferEnd); ok {
							seq := args.initRes.(*big.Int)
							if el.From == args.req.FromAddress && el.Sn == seq {
								return true
							}
						}
					} else if info.contractName == ctr.TokenIcon {
						if el, ok := info.eventLog.(*tokenIcon.TokenIconTransferEnd); ok {
							seq := args.initRes.(*big.Int)
							if el.From == args.req.FromAddress && el.Sn == seq {
								return true
							}
						}
					}
					return false
				},
			},
			{
				preRun: func(args args, info eventLogInfo) bool { // TransferStart msg on icon chain
					if info.sourceChain == chain.ICON && info.eventType == "TransferReceived" &&
						(info.contractName == ctr.NativeIcon || info.contractName == ctr.TokenIcon) {
						return true
					}
					return false
				},
				run: func(args args, info eventLogInfo) bool {
					if info.contractName == ctr.NativeIcon {
						if el, ok := info.eventLog.(*nativeIcon.NativeIconTransferReceived); ok {
							seq := args.initRes.(*big.Int)
							if el.From == args.req.FromAddress && el.Sn == seq {
								return true
							}
						}
					} else if info.contractName == ctr.TokenIcon {
						if el, ok := info.eventLog.(*tokenIcon.TokenIconTransferReceived); ok {
							seq := args.initRes.(*big.Int)
							if el.To == args.req.ToAddress && el.Sn == seq {
								return true
							}
						}
					}
					return false
				},
			},
		},
	},
}
