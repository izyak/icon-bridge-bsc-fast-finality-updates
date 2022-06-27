package ownerNativeHmy

import (
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/harmony-one/harmony/core/types"
	"github.com/icon-project/icon-bridge/cmd/endpoint/decoder/contracts"
)

type ownerNativeHmyContract struct {
	name          contracts.ContractName
	backend       bind.ContractBackend
	genObj        *OwnerNativeHmy
	eventIDToName map[common.Hash]string
}

func (b *ownerNativeHmyContract) GetName() contracts.ContractName {
	return b.name
}

func NewContract(name contracts.ContractName, url string, cAddr string) (contracts.Contract, error) {
	var err error
	clrpc, err := rpc.Dial(url)
	if err != nil {
		return nil, err
	}
	ctr := &ownerNativeHmyContract{name: name, backend: ethclient.NewClient(clrpc)}

	ctr.genObj, err = NewOwnerNativeHmy(common.HexToAddress(cAddr), ctr.backend)
	if err != nil {
		return nil, err
	}
	ctr.eventIDToName, err = contracts.EventIDToName(OwnerNativeHmyABI)
	if err != nil {
		return nil, err
	}
	return ctr, nil
}
func (b *ownerNativeHmyContract) Decode(l interface{}) (res map[string]interface{}, err error) {
	hlog, ok := l.(*types.Log)
	if !ok {
		return nil, errors.New("Log of wrong type. Expected types.Log")
	}
	log := ethTypes.Log{
		Address:     hlog.Address,
		Topics:      hlog.Topics,
		Data:        hlog.Data,
		BlockNumber: hlog.BlockNumber,
		TxHash:      hlog.TxHash,
		TxIndex:     hlog.TxIndex,
		BlockHash:   hlog.BlockHash,
		Index:       hlog.Index,
		Removed:     hlog.Removed,
	}
	res = map[string]interface{}{}
	for _, tid := range log.Topics {
		topicName, ok := b.eventIDToName[tid]
		if !ok {
			continue
		}
		if topicName == "RemoveOwnership" {
			if out, err := b.genObj.ParseRemoveOwnership(log); err != nil {
				return nil, err
			} else {
				res[topicName] = out
			}
		} else if topicName == "SetOwnership" {
			if out, err := b.genObj.ParseSetOwnership(log); err != nil {
				return nil, err
			} else {
				res[topicName] = out
			}
		}
	}
	return res, nil
}
