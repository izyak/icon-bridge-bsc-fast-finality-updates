package hmny

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/harmony-one/harmony/core/types"
	"github.com/icon-project/btp/common/errors"
	"github.com/icon-project/btp/common/log"
	"github.com/icon-project/btp/common/wallet"
)

const (
	BlockRetryInterval               = time.Second * 2
	DefaultReadTimeout               = 15 * time.Second
	BlockNotificationSyncConcurrency = 100 // number of concurrent requests to synchronize older blocks from source chain
)

type Client struct {
	log            log.Logger
	stopAllMonitor chan struct{}

	rpcs []*rpc.Client
	eths []*ethclient.Client
	bmcs []*BMC
}

func NewClient(urls []string, bmcAddr string, l log.Logger) *Client {
	cl := &Client{log: l, stopAllMonitor: make(chan struct{})}
	if len(urls) == 0 {
		l.Fatalf("invalid client urls: %v", urls)
	}
	for _, url := range urls {
		clrpc, err := rpc.Dial(url)
		if err != nil {
			l.Fatalf("failed to create harmony rpc client: %v", err)
		}
		cleth := ethclient.NewClient(clrpc)
		clbmc, err := NewBMC(HexToAddress(bmcAddr), cleth)
		if err != nil {
			l.Fatalf("failed to create bmc binding to ethclient: %v", err)
		}
		cl.rpcs = append(cl.rpcs, clrpc)
		cl.eths = append(cl.eths, cleth)
		cl.bmcs = append(cl.bmcs, clbmc)
	}
	return cl
}

func (cl *Client) rpc() *rpc.Client       { return cl.rpcs[rand.Intn(len(cl.rpcs))] }
func (cl *Client) eth() *ethclient.Client { return cl.eths[rand.Intn(len(cl.eths))] }
func (cl *Client) bmc() *BMC              { return cl.bmcs[rand.Intn(len(cl.bmcs))] }

func (cl *Client) newTransactOpts(w Wallet) *bind.TransactOpts {
	ew := w.(*wallet.EvmWallet)
	context := context.Background()
	chainID, _ := cl.eth().ChainID(context)
	txOpts, _ := bind.NewKeyedTransactorWithChainID(ew.Skey, chainID)
	txOpts.GasPrice, _ = cl.eth().SuggestGasPrice(context)
	txOpts.Context = context
	return txOpts
}

func (cl *Client) GetChainID() (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	return cl.eth().ChainID(ctx)
}

func (cl *Client) GetBlockNumber() (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	bn, err := cl.eth().BlockNumber(ctx)
	if err != nil {
		return 0, err
	}
	return bn, nil
}

func (cl *Client) GetTransaction(hash common.Hash) (*ethtypes.Transaction, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	tx, pending, err := cl.eth().TransactionByHash(ctx, hash)
	if err != nil {
		return nil, pending, err
	}
	return tx, pending, err
}

func (cl *Client) GetTransactionReceipt(hash common.Hash) (*types.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	tr := new(types.Receipt)
	err := cl.rpc().CallContext(ctx, tr, "hmy_getTransactionReceipt", hash)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

func (cl *Client) GetEpochLastBlock(epoch *big.Int) (*big.Int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	lbn := big.NewInt(0)
	err := cl.rpc().CallContext(ctx, lbn, "hmyv2_epochLastBlock", epoch)
	if err != nil {
		return nil, err
	}
	return lbn, nil
}

func (cl *Client) GetHmyBlockByHeight(height *big.Int) (*Block, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	hb := new(Block)
	err := cl.rpc().CallContext(ctx, hb, "hmyv2_getBlockByNumber", height, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	return hb, nil
}

func (cl *Client) rpcConsensusCall(
	threshold float64,
	method string,
	valfn func() interface{},
	keyfn func(val interface{}) interface{},
	args ...interface{}) (interface{}, error) {

	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()

	if threshold == 0 {
		val := valfn()
		err := cl.rpc().CallContext(ctx, val, method, args...)
		if err != nil {
			return nil, err
		}
		return val, nil
	}

	total := len(cl.rpcs)

	ech := make(chan error, total)
	vch := make(chan interface{}, total)
	for _, clr := range cl.rpcs {
		go func(clr *rpc.Client) {
			val := valfn()
			err := clr.CallContext(ctx, val, method, args...)
			if err != nil {
				val = nil
			}
			ech <- err
			vch <- val
		}(clr)
	}
	counts := make(map[interface{}]int, total)
	lookup := make(map[interface{}]interface{}, total)
	for i := 0; i < total; i++ {
		if val := <-vch; val != nil {
			key := keyfn(val)
			lookup[key] = val
			counts[key]++
		}
	}
	mk, mc := interface{}(nil), 0
	for k, c := range counts {
		if c > mc {
			mk, mc = k, c
		}
	}
	if mk == nil { // no response from any rpc client
		return nil, <-ech
	}
	consensus := float64(mc) / float64(total)
	if consensus < threshold {
		return nil, fmt.Errorf("consensus failure: %.2f/%.2f", consensus, threshold)
	}
	return lookup[mk], nil
}

func (cl *Client) GetHmyHeaderByHeight(height *big.Int, consensusThreshold float64) (*Header, error) {
	h, err := cl.rpcConsensusCall(
		consensusThreshold,
		"hmyv2_getFullHeader",
		func() interface{} { return &Header{} },
		func(val interface{}) interface{} {
			if val, ok := val.(*Header); ok {
				return val.Hash()
			}
			return nil
		},
		height)
	if err != nil {
		return nil, err
	}
	return h.(*Header), nil
}

func (cl *Client) GetBlockReceipts(hash common.Hash) ([]*types.Receipt, error) {
	return cl.getEthBlockReceipts(hash)
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	receipts := make([]*types.Receipt, 0)
	err := cl.rpc().CallContext(ctx, &receipts, "hmy_getBlockReceipts", hash)
	if err != nil {
		return nil, err
	}
	return receipts, nil
}

func (cl *Client) getEthBlockByHash(hash common.Hash) (*ethtypes.Block, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
	defer cancel()
	block, err := cl.eth().BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (cl *Client) getEthBlockReceipts(hash common.Hash) ([]*types.Receipt, error) {
	b, err := cl.getEthBlockByHash(hash)
	if err != nil {
		return nil, errors.Wrapf(err, "getEthBlockByHash: %v", err)
	}
	txns := b.Transactions()
	if b.GasUsed() == 0 || len(txns) == 0 {
		return nil, nil
	}
	// fetch all txn receipts concurrently
	type rcq struct {
		txh common.Hash
		v   *types.Receipt
		err error
	}
	rch := make(chan *rcq, len(txns))
	for _, tx := range txns {
		rch <- &rcq{tx.Hash(), nil, nil}
	}
	receipts := make([]*types.Receipt, 0, len(txns))
	for r := range rch {
		switch {
		case r.err != nil:
			// TODO handle too many requests error
			return nil, r.err
		case r.v != nil:
			receipts = append(receipts, r.v)
			if len(receipts) == cap(receipts) {
				close(rch)
			}
		default:
			go func(r *rcq) {
				defer func() { rch <- r }()
				ctx, cancel := context.WithTimeout(context.Background(), DefaultReadTimeout)
				defer cancel()
				v := &types.Receipt{}
				err := cl.rpc().CallContext(ctx, v, "hmy_getTransactionReceipt", r.txh)
				if err != nil {
					r.err = err
					return
				}
				r.v = v
			}(r)
		}
	}
	return receipts, nil
}

func (cl *Client) CloseAllMonitor() error {
	close(cl.stopAllMonitor)
	return nil
}

func (cl *Client) NewValidator(height uint64) (*Validator, error) {
	return newValidator(cl, new(big.Int).SetUint64(height))
}

// MonitorBlock subscribes to the new head notifications
func (cl *Client) MonitorBlock(startHeight uint64, fetchReceipts bool, cb func(v *BlockNotification) error) error {
	if startHeight == 0 {
		startHeight = 1
	}

	vl, err := cl.NewValidator(startHeight)
	if err != nil {
		return errors.Wrapf(err, "monitor block: NewValidator: %v", err)
	}

	// block notification channel (buffered: to avoid deadlock)
	bnch := make(chan *BlockNotification, BlockNotificationSyncConcurrency) // increase this for faster sync

	latest, next := int64(0), int64(startHeight)

	poll := time.NewTicker(time.Second)
	defer poll.Stop()

	// last unverified block notification
	var lbn *BlockNotification

	// start monitor loop
	for {
		select {
		case <-cl.stopAllMonitor:
			return nil

		case <-poll.C:
			n, err := cl.GetBlockNumber()
			if err != nil {
				continue
				// return errors.Wrapf(err,
				// 	"monitor block: poll block number: %v", err)
			}
			if int64(n) <= latest {
				continue
			}
			latest = int64(n)
			if next > latest {
				cl.log.Debugf(
					"monitor block: skipping; latest=%d, next=%d",
					latest, next)
			}

		case bn := <-bnch:
			// process all notifications
			for ; bn != nil; next++ {
				if lbn != nil {
					ok, err := vl.verify(lbn.Header, bn.Header)
					if err != nil {
						cl.log.Errorf("monitor block: signature validation failed: h=%d, %v", lbn.Header.Number, err)
						break
					}
					if !ok {
						cl.log.Errorf("monitor block: invalid header: signature validation failed: h=%d", lbn.Header.Number)
						break
					}
					if err := cb(lbn); err != nil {
						return errors.Wrapf(err, "monitor block: callback: %v", err)
					}
					if err := vl.update(lbn.Header); err != nil {
						return errors.Wrapf(err, "monitor block: update validator: %v", err)
					}
				}
				if lbn, bn = bn, nil; len(bnch) > 0 {
					bn = <-bnch
				}
			}
			// remove unprocessed notifications
			for len(bnch) > 0 {
				<-bnch
			}

		default:
			if next >= latest {
				time.Sleep(time.Millisecond)
				continue
			}

			type bnq struct {
				h     int64
				v     *BlockNotification
				err   error
				retry int
			}

			qch := make(chan *bnq, cap(bnch))
			for i := next; i < latest &&
				len(qch) < cap(qch); i++ {
				qch <- &bnq{i, nil, nil, 3} // fill bch with requests
			}
			bns := make([]*BlockNotification, 0, len(qch))
			for q := range qch {
				switch {
				case q.v != nil:
					bns = append(bns, q.v)
					if len(bns) == cap(bns) {
						close(qch)
					}
				case q.err != nil:
					if q.retry > 0 {
						q.retry--
						q.v, q.err = nil, nil
						qch <- q
					} else {
						cl.log.Errorf("monitor block: bnq: h=%d:%v, %v", q.h, q.v.Header.Hash(), q.err)
						bns = append(bns, nil)
						if len(bns) == cap(bns) {
							close(qch)
						}
						// return errors.Wrapf(r.err,
						// 	"monitor block: h=%d, %v", r.h, r.err)
					}
				default:
					go func(q *bnq) (err error) {
						defer func() { qch <- q }()
						v := &BlockNotification{Height: big.NewInt(q.h)}
						v.Header, err = cl.GetHmyHeaderByHeight(v.Height, 0)
						if err != nil {
							q.err = errors.Wrapf(err, "GetHmyHeaderByHeight: %v", err)
							return
						}
						v.Hash = v.Header.Hash()
						q.v = v
						if fetchReceipts && v.Header.GasUsed > 0 {
							v.Receipts, err = cl.GetBlockReceipts(v.Hash)
							if err == nil {
								var tr *trie.Trie
								tr, err = receiptsTrie(v.Receipts)
								if err == nil {
									if !bytes.Equal(tr.Hash().Bytes(), v.Header.ReceiptsRoot.Bytes()) {
										err = fmt.Errorf(
											"invalid receipts: root=%v, trie=%v",
											v.Header.ReceiptsRoot, tr.Hash())
									}
								}
							}
							if err != nil {
								q.err = errors.Wrapf(err, "GetBlockReceipts: %v", err)
								return
							}
						}
						q.v = v
						return
					}(q)
				}
			}
			// filter nil
			_bns_, bns := bns, bns[:0]
			for _, v := range _bns_ {
				if v != nil {
					bns = append(bns, v)
				}
			}
			// sort and forward notifications
			if len(bns) > 0 {
				sort.SliceStable(bns, func(i, j int) bool {
					return bns[i].Height.Int64() < bns[j].Height.Int64()
				})
				for i, v := range bns {
					if v.Height.Int64() == next+int64(i) {
						bnch <- v
					}
				}
			}
		}

	}
}
