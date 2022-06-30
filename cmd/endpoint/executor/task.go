package executor

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/icon-project/icon-bridge/cmd/endpoint/chain"
	"github.com/icon-project/icon-bridge/common/errors"
	"github.com/icon-project/icon-bridge/common/log"
)

const (
	PRIVKEYPOS = 0
	PUBKEYPOS  = 1
)

type evt struct {
	msg  *chain.EventLogInfo
	name chain.ChainType
}

type args struct {
	id              uint64
	log             log.Logger
	clientsPerChain map[chain.ChainType]chain.ChainAPI
	godKeysPerChain map[chain.ChainType][2]string
	addrToName      map[string]chain.ContractName
	sinkChan        <-chan *evt
	closeFunc       func()
}

func newArgs(id uint64, l log.Logger,
	clientsPerChain map[chain.ChainType]chain.ChainAPI,
	godKeysPerChain map[chain.ChainType][2]string,
	addrToName map[string]chain.ContractName,
	sinkChan <-chan *evt, closeFunc func(),
) (t *args, err error) {
	tu := &args{log: l, id: id,
		clientsPerChain: clientsPerChain,
		godKeysPerChain: godKeysPerChain,
		addrToName:      addrToName,
		sinkChan:        sinkChan,
		closeFunc:       closeFunc,
	}

	return tu, nil
}

type callBackFunc func(ctx context.Context, args *args) error

var DemoSubCallback callBackFunc = func(ctx context.Context, args *args) error {

	// fund demo wallets
	args.log.Info("Starting demo...")
	ienv, ok := args.clientsPerChain[chain.ICON]
	if !ok {
		return errors.New("Icon client not found")
	}
	henv, ok := args.clientsPerChain[chain.HMNY]
	if !ok {
		return errors.New("Hmny client not found")
	}
	igod, ok := args.godKeysPerChain[chain.ICON]
	if !ok {
		return errors.New("God Keys not found for ICON")
	}
	hgod, ok := args.godKeysPerChain[chain.HMNY]
	if !ok {
		return errors.New("God keys not found for Hmy")
	}
	tmp, err := ienv.GetKeyPairs(1)
	if err != nil {
		return errors.New("Couldn't create demo account for icon")
	}
	iDemo := tmp[0]
	tmp, err = henv.GetKeyPairs(1)
	if err != nil {
		return errors.New("Couldn't create demo account for hmny")
	}
	hDemo := tmp[0]
	args.log.Info("Creating Demo Icon Account ", iDemo)
	args.log.Info("Creating Demo Hmy Account ", hDemo)
	findAddrForContract := func(inputName chain.ContractName) (retAddr string, ok bool) {
		for addr, name := range args.addrToName {
			if name == inputName {
				return addr, true
			}
		}
		return "", false
	}
	watchTransferStart := func(elInfo []*chain.EventLogInfo) error {
		for _, el := range elInfo {
			if el.EventType != chain.TransferStart {
				continue
			}
			seq, err := el.GetSeq()
			if err != nil {
				return err
			}
			ctrName, ok := args.addrToName[el.ContractAddress]
			if !ok {
				return fmt.Errorf("Event %v generated by %v is not in config", el.EventType, el.ContractAddress)
			}
			args.log.Infof("Generated event %v contractName %v SeqNo %v", el.EventType, ctrName, seq)
			if ctrName == chain.NativeBSHIcon {
				if ctr, ok := findAddrForContract(chain.NativeBSHPeripheryHmy); ok {
					henv.WatchFor(args.id, chain.TransferReceived, seq, ctr)
					ienv.WatchFor(args.id, chain.TransferEnd, seq, el.ContractAddress)
				} else {
					return errors.New("NativeBSHPeripheryHmy does not exist in config")
				}
			} else if ctrName == chain.NativeBSHPeripheryHmy {
				if ctr, ok := findAddrForContract(chain.NativeBSHIcon); ok {
					henv.WatchFor(args.id, chain.TransferEnd, seq, el.ContractAddress)
					ienv.WatchFor(args.id, chain.TransferReceived, seq, ctr)
				} else {
					return errors.New("NativeBSHIcon does not exist in config")
				}
			} else if ctrName == chain.TokenBSHIcon {
				if ctr, ok := findAddrForContract(chain.TokenBSHImplHmy); ok {
					henv.WatchFor(args.id, chain.TransferReceived, seq, ctr)
					ienv.WatchFor(args.id, chain.TransferEnd, seq, el.ContractAddress)
				} else {
					return errors.New("TokenBSHImplHmy does not exist in config")
				}
			} else if ctrName == chain.TokenBSHImplHmy {
				if ctr, ok := findAddrForContract(chain.TokenBSHIcon); ok {
					henv.WatchFor(args.id, chain.TransferEnd, seq, el.ContractAddress)
					ienv.WatchFor(args.id, chain.TransferReceived, seq, ctr)
				} else {
					return errors.New("NativeBSHIcon does not exist in config")
				}
			} else {
				args.log.Warnf("Unexpected contract name %v ", ctrName)
			}
		}
		return nil
	}

	args.log.Info("Funding Demo Wallets ")
	amt := new(big.Int)
	amt.SetString("250000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.ICON, SenderKey: igod[PRIVKEYPOS], FromAddress: igod[PUBKEYPOS], ToAddress: iDemo[PUBKEYPOS], Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.ICON, SenderKey: igod[PRIVKEYPOS], FromAddress: igod[PUBKEYPOS], ToAddress: iDemo[PUBKEYPOS], Amount: *amt, Token: chain.IRC2Token})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.HMNY, SenderKey: hgod[PRIVKEYPOS], FromAddress: hgod[PUBKEYPOS], ToAddress: hDemo[PUBKEYPOS], Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.HMNY, SenderKey: hgod[PRIVKEYPOS], FromAddress: hgod[PUBKEYPOS], ToAddress: hDemo[PUBKEYPOS], Amount: *amt, Token: chain.ERC20Token})
	if err != nil {
		return err
	}
	args.log.Info("Done funding")
	time.Sleep(time.Second * 10)
	go func(ctx context.Context) {
		args.log.Info("Starting Watch")
		defer args.closeFunc()
		counter := 0
		for {
			select {
			case <-ctx.Done():
				args.log.Warn("Context Cancelled Exiting task")
				return
			case res := <-args.sinkChan:
				args.log.Infof("%v: %+v", res.name, res.msg)
				counter += 1
				if counter >= 4 { // 2 Watch calls * 2 TxEvents{End,Rx}
					args.log.Infof("Received all events. Closing...")
					return
				}
			}
		}

	}(ctx)
	time.Sleep(time.Second * 15)

	args.log.Info("Transfer Native ICX to HMY")
	amt = new(big.Int)
	amt.SetString("2000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.HMNY, SenderKey: iDemo[PRIVKEYPOS], FromAddress: iDemo[PUBKEYPOS], ToAddress: *henv.GetBTPAddress(hDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	args.log.Info("Transfer Native ONE to ICX")
	amt = new(big.Int)
	amt.SetString("2000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.ICON, SenderKey: hDemo[PRIVKEYPOS], FromAddress: hDemo[PUBKEYPOS], ToAddress: *ienv.GetBTPAddress(iDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	args.log.Info("Approve")
	time.Sleep(time.Second * 10)

	amt = new(big.Int)
	amt.SetString("100000000000000000000000", 10)
	_, err = ienv.Approve(iDemo[PRIVKEYPOS], *amt)
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("100000000000000000000000", 10)
	_, err = henv.Approve(hDemo[PRIVKEYPOS], *amt)
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)

	args.log.Info("Transfer Wrapped")
	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	hash, err := ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.HMNY, SenderKey: iDemo[PRIVKEYPOS], FromAddress: iDemo[PUBKEYPOS], ToAddress: *henv.GetBTPAddress(hDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	_, elInfo, err := ienv.WaitForTxnResult(ctx, hash)
	if err != nil {
		return err
	}
	watchTransferStart(elInfo)

	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	hash, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.ICON, SenderKey: hDemo[PRIVKEYPOS], FromAddress: hDemo[PUBKEYPOS], ToAddress: *ienv.GetBTPAddress(iDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	_, elInfo, err = henv.WaitForTxnResult(ctx, hash)
	if err != nil {
		return err
	}
	watchTransferStart(elInfo)

	return nil
}

var DemoRequestCallback callBackFunc = func(ctx context.Context, args *args) error {
	defer args.closeFunc()
	// fund demo wallets
	args.log.Info("Starting demo...")
	ienv, ok := args.clientsPerChain[chain.ICON]
	if !ok {
		return errors.New("Icon client not found")
	}
	henv, ok := args.clientsPerChain[chain.HMNY]
	if !ok {
		return errors.New("Hmny client not found")
	}
	igod, ok := args.godKeysPerChain[chain.ICON]
	if !ok {
		return errors.New("God Keys not found for ICON")
	}
	hgod, ok := args.godKeysPerChain[chain.HMNY]
	if !ok {
		return errors.New("God keys not found for Hmy")
	}
	tmp, err := ienv.GetKeyPairs(1)
	if err != nil {
		return errors.New("Couldn't create demo account for icon")
	}
	iDemo := tmp[0]
	tmp, err = henv.GetKeyPairs(1)
	if err != nil {
		return errors.New("Couldn't create demo account for hmny")
	}
	hDemo := tmp[0]
	args.log.Info("Creating Demo Icon Account ", iDemo)
	args.log.Info("Creating Demo Hmy Account ", hDemo)
	showBalance := func(log log.Logger, env chain.ChainAPI, addr string, tokens []chain.TokenType) error {
		factor := new(big.Int)
		factor.SetString("10000000000000000", 10)
		for _, token := range tokens {
			if amt, err := env.GetCoinBalance(addr, token); err != nil {
				return err
			} else {
				log.Infof("%v: %v", token, amt.Div(amt, factor).String())
			}
		}
		return nil
	}
	args.log.Info("Funding Demo Wallets ")
	amt := new(big.Int)
	amt.SetString("250000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.ICON, SenderKey: igod[PRIVKEYPOS], FromAddress: igod[PUBKEYPOS], ToAddress: iDemo[PUBKEYPOS], Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.ICON, SenderKey: igod[PRIVKEYPOS], FromAddress: igod[PUBKEYPOS], ToAddress: iDemo[PUBKEYPOS], Amount: *amt, Token: chain.IRC2Token})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.HMNY, SenderKey: hgod[PRIVKEYPOS], FromAddress: hgod[PUBKEYPOS], ToAddress: hDemo[PUBKEYPOS], Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("10000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.HMNY, SenderKey: hgod[PRIVKEYPOS], FromAddress: hgod[PUBKEYPOS], ToAddress: hDemo[PUBKEYPOS], Amount: *amt, Token: chain.ERC20Token})
	if err != nil {
		return err
	}
	args.log.Info("Done funding")
	time.Sleep(time.Second * 10)
	// args.log.Info("ICON:  ")
	// if err := showBalance(args.log, ienv, iDemo[PUBKEYPOS], []chain.TokenType{chain.ICXToken, chain.IRC2Token, chain.ONEToken}); err != nil {
	// 	return err
	// }
	// args.log.Info("HMNY:   ")
	// if err := showBalance(args.log, henv, hDemo[PUBKEYPOS], []chain.TokenType{chain.ONEToken, chain.ERC20Token, chain.ICXToken}); err != nil {
	// 	return err
	// }

	args.log.Info("Transfer Native ICX to HMY")
	amt = new(big.Int)
	amt.SetString("2000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.HMNY, SenderKey: iDemo[PRIVKEYPOS], FromAddress: iDemo[PUBKEYPOS], ToAddress: *henv.GetBTPAddress(hDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	args.log.Info("Transfer Native ONE to ICX")
	amt = new(big.Int)
	amt.SetString("2000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.ICON, SenderKey: hDemo[PRIVKEYPOS], FromAddress: hDemo[PUBKEYPOS], ToAddress: *ienv.GetBTPAddress(iDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	args.log.Info("Approve")
	time.Sleep(time.Second * 10)

	amt = new(big.Int)
	amt.SetString("100000000000000000000000", 10)
	_, err = ienv.Approve(iDemo[PRIVKEYPOS], *amt)
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("100000000000000000000000", 10)
	_, err = henv.Approve(hDemo[PRIVKEYPOS], *amt)
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)

	args.log.Info("Transfer Wrapped")
	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.ICON, SenderKey: hDemo[PRIVKEYPOS], FromAddress: hDemo[PUBKEYPOS], ToAddress: *ienv.GetBTPAddress(iDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ICXToken})
	if err != nil {
		return err
	}
	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.HMNY, SenderKey: iDemo[PRIVKEYPOS], FromAddress: iDemo[PUBKEYPOS], ToAddress: *henv.GetBTPAddress(hDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ONEToken})
	if err != nil {
		return err
	}
	time.Sleep(10 * time.Second)

	args.log.Info("Transfer Irc2 to HMY")
	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	_, err = ienv.Transfer(&chain.RequestParam{FromChain: chain.ICON, ToChain: chain.HMNY, SenderKey: iDemo[PRIVKEYPOS], FromAddress: iDemo[PUBKEYPOS], ToAddress: *henv.GetBTPAddress(hDemo[PUBKEYPOS]), Amount: *amt, Token: chain.IRC2Token})
	if err != nil {
		return err
	}
	args.log.Info("Transfer Erc20 to ICon")
	amt = new(big.Int)
	amt.SetString("1000000000000000000", 10)
	_, err = henv.Transfer(&chain.RequestParam{FromChain: chain.HMNY, ToChain: chain.ICON, SenderKey: hDemo[PRIVKEYPOS], FromAddress: hDemo[PUBKEYPOS], ToAddress: *ienv.GetBTPAddress(iDemo[PUBKEYPOS]), Amount: *amt, Token: chain.ERC20Token})
	if err != nil {
		return err
	}
	time.Sleep(30 * time.Second)
	args.log.Info("ICON:  ")
	if err := showBalance(args.log, ienv, iDemo[PUBKEYPOS], []chain.TokenType{chain.ICXToken, chain.IRC2Token, chain.ONEToken}); err != nil {
		return err
	}
	args.log.Info("HMNY:   ")
	if err := showBalance(args.log, henv, hDemo[PUBKEYPOS], []chain.TokenType{chain.ONEToken, chain.ERC20Token, chain.ICXToken}); err != nil {
		return err
	}
	args.log.Info("Done")
	return nil
}
