package bsc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethCommon "github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/icon-project/icon-bridge/cmd/iconbridge/chain"
	"github.com/icon-project/icon-bridge/cmd/iconbridge/chain/bsc/types"
	"github.com/icon-project/icon-bridge/common/log"
	"github.com/icon-project/icon-bridge/common/queue"
	"github.com/pkg/errors"
)

const (
	BlockInterval              = 3 * time.Second
	BlockHeightPollInterval    = BlockInterval * 5
	BlockFinalityConfirmations = 10
	MonitorBlockMaxConcurrency = 300 // number of concurrent requests to synchronize older blocks from source chain
	RPCCallRetry               = 5
)

var (
	bscVerifierSnapshot string
)

func init() {
	flag.StringVar(&bscVerifierSnapshot, "verifier config", "bscVerifierSnapshot.json", "verifier Snapshot .json file")
}

func NewReceiver(
	src, dst chain.BTPAddress, urls []string,
	rawOpts json.RawMessage, l log.Logger) (chain.Receiver, error) {
	r := &receiver{
		log: l,
		src: src,
		dst: dst,
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("empty urls: %v", urls)
	}
	err := json.Unmarshal(rawOpts, &r.opts)
	if err != nil {
		return nil, err
	}
	if r.opts.SyncConcurrency < 1 {
		r.opts.SyncConcurrency = 1
	} else if r.opts.SyncConcurrency > MonitorBlockMaxConcurrency {
		r.opts.SyncConcurrency = MonitorBlockMaxConcurrency
	}

	r.cls, err = newClients(urls, src.ContractAddress(), r.log)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type ReceiverOptions struct {
	SyncConcurrency uint64           `json:"syncConcurrency"`
	Verifier        *VerifierOptions `json:"verifier"`
}

func (opts *ReceiverOptions) Unmarshal(v map[string]interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, opts)
}

type receiver struct {
	log  log.Logger
	src  chain.BTPAddress
	dst  chain.BTPAddress
	opts ReceiverOptions
	cls  []IClient
}

func (r *receiver) client() IClient {
	randInt := rand.Intn(len(r.cls))
	return r.cls[randInt]
}

type BnOptions struct {
	StartHeight uint64
	Concurrency uint64
}

func (r *receiver) newVerifier(ctx context.Context, opts *VerifierOptions) (vri IVerifier, err error) {
	// TODO: Add parentHeaders
	snapshotVerifier := loadBscVerifierConfig(bscVerifierSnapshot)
	if snapshotVerifier != nil {
		opts = snapshotVerifier
	}
	
	vr := &Verifier{
		mu:                         sync.RWMutex{},
		next:                       big.NewInt(int64(opts.BlockHeight)),
		validators:                 map[ethCommon.Address]bool{},
		prevValidators:             map[ethCommon.Address]bool{},
		useNewValidatorsFromHeight: big.NewInt(int64(opts.BlockHeight)),
		chainID:                    r.client().GetChainID(),
		log: r.log.WithFields(
			log.Fields{
				log.FieldKeyPrefix: "vr_",
			},
		),
	}


	// cross check input parent hash
	header, err := r.client().GetHeaderByHeight(ctx, big.NewInt(int64(opts.BlockHeight)))
	if err != nil {
		err = errors.Wrapf(err, "GetHeaderByHeight: %v", err)
		return nil, err
	}
	vr.parentHash = header.ParentHash

	if isLubanBlock(header.Number) {
		justifiedHeader, err := r.client().GetHeaderByHeight(ctx, big.NewInt(int64(opts.JustifiedBlockHeight)))
		if err != nil {
			return nil, err
		}
		headerVoteAttestation, err := getVoteAttestationFromHeader(header)

		if headerVoteAttestation.Data.SourceNumber != justifiedHeader.Number.Uint64() || headerVoteAttestation.Data.SourceHash != justifiedHeader.Hash() {
			return nil, errors.Wrapf(err, "Block height %v does not have valid attestation for justified block: %v", header.Number, justifiedHeader.Number)
		}
		vr.latestJustifiedHeader = justifiedHeader
	}

	roundedHeight := big.NewInt(int64(opts.BlockHeight - opts.BlockHeight%defaultEpochLength))
	// cross check input validator data
	if opts.BlockHeight%defaultEpochLength == 0 {
		roundedHeight = big.NewInt(int64(opts.BlockHeight - defaultEpochLength))
	}
	roundedHeader, err := r.client().GetHeaderByHeight(ctx, roundedHeight)
	if err != nil {
		err = errors.Wrapf(err, "GetHeaderByHeight: %v", err)
		return nil, err
	}

	if !bytes.Equal(roundedHeader.Extra, opts.ValidatorData) {
		return nil, fmt.Errorf("Unexpected ValidatorData(%v): Got %v Expected %v", roundedHeight, hex.EncodeToString(roundedHeader.Extra), opts.ValidatorData)
	}

	vr.validators, vr.blsPubKeys, err = parseValidators(roundedHeader)
	if err != nil {
		return nil, errors.Wrapf(err, "getValidatorMapFromHex %v", err)
	}
	return vr, nil
}

func loadBscVerifierConfig(file string) *VerifierOptions {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	cfg := &VerifierOptions{}
	err = json.NewDecoder(f).Decode(cfg)
	if err != nil {
		return nil
	}
	return cfg
}

func (r *receiver) syncVerifier(ctx context.Context, vr IVerifier, height int64) error {
	if height == vr.Next().Int64() {
		return nil
	}
	if vr.Next().Int64() > height {
		return fmt.Errorf(
			"invalid target height: verifier height (%s) > target height (%d)",
			vr.Next().String(), height)
	}

	type res struct {
		Height int64
		Header *ethTypes.Header
	}

	type req struct {
		height int64
		err    error
		res    *res
		retry  int64
	}

	r.log.WithFields(log.Fields{"height": vr.Next().String(), "target": height}).Info("syncVerifier: start")

	unfinalizedBlocks := queue.NewQueue(BlockFinalityConfirmations) // queue of blocks whose attestation could not be verified
	var lastBlock *ethTypes.Header                                  // last block whose attestation was to be verified
	var justifiedBlock *ethTypes.Header                             // latest justified block

	cursor := vr.Next().Int64()
	for cursor <= height {
		rqch := make(chan *req, r.opts.SyncConcurrency)
		for i := cursor; len(rqch) < cap(rqch); i++ {
			rqch <- &req{height: i, retry: 5}
		}
		sres := make([]*res, 0, len(rqch))
		for q := range rqch {
			switch {
			case q.err != nil:
				if q.retry > 0 {
					q.retry--
					q.res, q.err = nil, nil
					rqch <- q
					continue
				}
				r.log.WithFields(log.Fields{"height": q.height, "error": q.err.Error()}).Debug("syncVerifier: req error")
				sres = append(sres, nil)
				if len(sres) == cap(sres) {
					close(rqch)
				}
			case q.res != nil:
				sres = append(sres, q.res)
				if len(sres) == cap(sres) {
					close(rqch)
				}
			default:
				go func(q *req) {
					defer func() {
						time.Sleep(500 * time.Millisecond)
						rqch <- q
					}()
					if q.res == nil {
						q.res = &res{}
					}
					q.res.Height = q.height
					q.res.Header, q.err = r.client().GetHeaderByHeight(ctx, big.NewInt(q.height))
					if q.err != nil {
						q.err = errors.Wrapf(q.err, "syncVerifier: getBlockHeader: %v", q.err)
						return
					}
				}(q)
			}
		}
		// filter nil
		_sres, sres := sres, sres[:0]
		for _, v := range _sres {
			if v != nil {
				sres = append(sres, v)
			}
		}
		// sort and forward notifications
		if len(sres) > 0 {
			sort.SliceStable(sres, func(i, j int) bool {
				return sres[i].Height < sres[j].Height
			})
			for i := range sres {
				cursor++
				next := sres[i]
				if lastBlock == nil {
					lastBlock = next.Header
					continue
				}
				if vr.Next().Int64() >= height { // if height is greater than targetHeight, break loop
					break
				}
				err, lastBlockIsJustified := vr.Verify(lastBlock, next.Header, nil)
				if err != nil {
					r.log.WithFields(log.Fields{
						"height":     lastBlock.Number,
						"lbnHash":    lastBlock.Hash,
						"nextHeight": next,
						"bnHash":     next.Header.Hash()}).Error("verification failed. refetching block ", err)
					cursor = int64(lastBlock.Number.Uint64()) - 1
					lastBlock = nil
					break
				}

				if !lastBlockIsJustified {
					if err := unfinalizedBlocks.Enqueue(lastBlock); err != nil {
						unfinalizedBlocks.Dequeue() // always dequeue if the queue is full
						unfinalizedBlocks.Enqueue(lastBlock)
					}

				} else {
					justifiedBlock = lastBlock
					for unfinalizedBlocks.Len() > 0 {
						_, err := unfinalizedBlocks.Dequeue()
						if err != nil {
							break
						}
					}
					unfinalizedBlocks.Enqueue(justifiedBlock)
				}

				if err := vr.Update(justifiedBlock, next.Header); err != nil {
					return errors.Wrapf(err, "syncVerifier: Update: %v", err)
				}

				lastBlock = next.Header
			}
			r.log.WithFields(log.Fields{"height": vr.Next().String(), "target": height}).Debug("syncVerifier: syncing")
		}
	}

	r.log.WithFields(log.Fields{"height": vr.Next().String()}).Info("syncVerifier: complete")
	return nil
}

func (r *receiver) receiveLoop(ctx context.Context, opts *BnOptions, callback func(v *types.BlockNotification) error) (err error) {

	if opts == nil {
		return errors.New("receiveLoop: invalid options: <nil>")
	}

	var vr IVerifier
	if r.opts.Verifier != nil {
		vr, err = r.newVerifier(ctx, r.opts.Verifier)
		if err != nil {
			return err
		}
		err = r.syncVerifier(ctx, vr, int64(opts.StartHeight))
		if err != nil {
			return errors.Wrapf(err, "receiveLoop: syncVerifier: %v", err)
		}
	}

	// block notification channel
	// (buffered: to avoid deadlock)
	// increase concurrency parameter for faster sync
	bnch := make(chan *types.BlockNotification, r.opts.SyncConcurrency)

	heightTicker := time.NewTicker(BlockInterval)
	defer heightTicker.Stop()

	heightPoller := time.NewTicker(BlockHeightPollInterval)
	defer heightPoller.Stop()

	latestHeight := func() uint64 {
		height, err := r.client().GetBlockNumber()
		if err != nil {
			r.log.WithFields(log.Fields{"error": err}).Error("receiveLoop: failed to GetBlockNumber")
			return 0
		}
		return height - BlockFinalityConfirmations
	}
	next, latest := opts.StartHeight, latestHeight() // TODO change next

	unfinalizedBlocks := queue.NewQueue(BlockFinalityConfirmations) // queue of blocks whose attestation could not be verified
	var lastBlock *types.BlockNotification                          // block whose attestation was to be verified
	var justifiedBlock *types.BlockNotification                     // latest justified block

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-heightTicker.C:
			latest++

		case <-heightPoller.C:
			if height := latestHeight(); height > 0 {
				latest = height
				r.log.WithFields(log.Fields{"latest": latest, "next": next}).Debug("poll height")
			}

		case bn := <-bnch:
			// process all notifications
			for ; bn != nil; next++ {
				if lastBlock != nil {
					if bn.Height.Cmp(lastBlock.Height) == 0 {
						if bn.Header.ParentHash != lastBlock.Header.ParentHash {
							r.log.WithFields(log.Fields{"lbnParentHash": lastBlock.Header.ParentHash, "bnParentHash": bn.Header.ParentHash}).Error("verification failed on retry ")
							break
						}
					} else {
						if vr != nil {
							err, lastBlockIsJustified := vr.Verify(lastBlock.Header, bn.Header, bn.Receipts)
							if err != nil {
								r.log.WithFields(log.Fields{
									"height":     lastBlock.Height,
									"lbnHash":    lastBlock.Hash,
									"nextHeight": next,
									"bnHash":     bn.Hash}).Error("verification failed. refetching block ", err)
								next = lastBlock.Header.Number.Uint64()
								lastBlock = nil
								break
							}

							if !lastBlockIsJustified {
								if err := unfinalizedBlocks.Enqueue(lastBlock); err != nil {
									_bn, _ := unfinalizedBlocks.Dequeue()
									bn := _bn.(*types.BlockNotification)
									if err := callback(bn); err != nil {
										return errors.Wrapf(err, "receiveLoop: callback: %v", err)
									}
									unfinalizedBlocks.Enqueue(lastBlock)
								}

							} else {
								justifiedBlock = lastBlock

								for unfinalizedBlocks.Len() > 0 {
									lbn, err := unfinalizedBlocks.Dequeue()
									if err != nil {
										break
									}
									bn := lbn.(*types.BlockNotification)
									if err := callback(bn); err != nil {
										return errors.Wrapf(err, "receiveLoop: callback: %v", err)
									}
								}
								unfinalizedBlocks.Enqueue(justifiedBlock)

								lastBlockHeight := lastBlock.Header.Number.Uint64()
								if lastBlockHeight%1000 == 0 {

									roundedHeight := big.NewInt(int64(lastBlockHeight - defaultEpochLength))

									roundedHeader, _ := r.client().GetHeaderByHeight(ctx, roundedHeight)

									VerifierOptsSnapshot(&VerifierOptions{
										BlockHeight:          lastBlockHeight,
										JustifiedBlockHeight: lastBlockHeight - 1,
										ValidatorData:        roundedHeader.Extra,
									})
								}

							}

							if err := vr.Update(justifiedBlock.Header, bn.Header); err != nil {
								return errors.Wrapf(err, "receiveLoop: vr.Update: %v", err)
							}
						}
					}
				}
				if lastBlock, bn = bn, nil; len(bnch) > 0 {
					bn = <-bnch
				}
			}
			// remove unprocessed notifications
			for len(bnch) > 0 {
				<-bnch
			}

		default:
			if next >= latest {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			type bnq struct {
				h     uint64
				v     *types.BlockNotification
				err   error
				retry int
			}
			qch := make(chan *bnq, cap(bnch))
			for i := next; i < latest &&
				len(qch) < cap(qch); i++ {
				qch <- &bnq{i, nil, nil, RPCCallRetry} // fill bch with requests
			}
			if len(qch) == 0 {
				r.log.Error("Fatal: Zero length of query channel. Avoiding deadlock")
				continue
			}
			bns := make([]*types.BlockNotification, 0, len(qch))
			for q := range qch {
				switch {
				case q.err != nil:
					if q.retry > 0 {
						q.retry--
						q.v, q.err = nil, nil
						qch <- q
						continue
					}
					r.log.Debugf("receiveLoop: bnq: h=%d:%v, %v", q.h, q.v.Header.Hash(), q.err)
					bns = append(bns, nil)
					if len(bns) == cap(bns) {
						close(qch)
					}

				case q.v != nil:
					bns = append(bns, q.v)
					if len(bns) == cap(bns) {
						close(qch)
					}
				default:
					go func(q *bnq) {
						defer func() {
							time.Sleep(500 * time.Millisecond)
							qch <- q
						}()

						if q.v == nil {
							q.v = &types.BlockNotification{}
						}

						q.v.Height = (&big.Int{}).SetUint64(q.h)

						if q.v.Header == nil {
							header, err := r.client().GetHeaderByHeight(ctx, q.v.Height)
							if err != nil {
								q.err = errors.Wrapf(err, "GetHeaderByHeight: %v", err)
								return
							}
							q.v.Header = header
							q.v.Hash = q.v.Header.Hash()
						}
						if q.v.Header.GasUsed > 0 {
							if q.v.HasBTPMessage == nil {
								hasBTPMessage, err := r.hasBTPMessage(ctx, q.v.Height)
								if err != nil {
									q.err = errors.Wrapf(err, "hasBTPMessage: %v", err)
									return
								}
								q.v.HasBTPMessage = &hasBTPMessage
							}
							if !*q.v.HasBTPMessage {
								return
							}
							// TODO optimize retry of GetBlockReceipts()
							q.v.Receipts, q.err = r.client().GetBlockReceipts(q.v.Hash)
							if q.err != nil {
								q.err = errors.Wrapf(q.err, "GetBlockReceipts: %v", q.err)
								return
							}
						}
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
					return bns[i].Height.Uint64() < bns[j].Height.Uint64()
				})
				for i, v := range bns {
					if v.Height.Uint64() == next+uint64(i) {
						bnch <- v
					}
				}
			}
		}
	}
}

func (r *receiver) hasBTPMessage(ctx context.Context, height *big.Int) (bool, error) {
	ctxNew, cancel := context.WithTimeout(ctx, defaultReadTimeout)
	defer cancel()
	logs, err := r.client().FilterLogs(ctxNew, ethereum.FilterQuery{
		FromBlock: height,
		ToBlock:   height,
		Addresses: []ethCommon.Address{ethCommon.HexToAddress(r.src.ContractAddress())},
	})
	if err != nil {
		return false, errors.Wrapf(err, "FilterLogs %v", err)
	}
	if len(logs) > 0 {
		return true, nil
	}
	return false, nil
}

func (r *receiver) Subscribe(
	ctx context.Context, msgCh chan<- *chain.Message,
	opts chain.SubscribeOptions) (errCh <-chan error, err error) {

	opts.Seq++

	_errCh := make(chan error)

	go func() {
		defer close(_errCh)
		lastHeight := opts.Height - 1
		if err := r.receiveLoop(ctx,
			&BnOptions{
				StartHeight: opts.Height,
				Concurrency: r.opts.SyncConcurrency,
			},
			func(v *types.BlockNotification) error {
				r.log.WithFields(log.Fields{"height": v.Height}).Debug("block notification")

				if v.Height.Uint64() != lastHeight+1 {
					r.log.Errorf("expected v.Height == %d, got %d", lastHeight+1, v.Height.Uint64())
					return fmt.Errorf(
						"block notification: expected=%d, got=%d",
						lastHeight+1, v.Height.Uint64())
				}

				receipts := r.getRelayReceipts(v)
				for _, receipt := range receipts {
					events := receipt.Events[:0]
					for _, event := range receipt.Events {
						switch {
						case event.Sequence == opts.Seq:
							events = append(events, event)
							opts.Seq++
						case event.Sequence > opts.Seq:
							r.log.WithFields(log.Fields{
								"seq": log.Fields{"got": event.Sequence, "expected": opts.Seq},
							}).Error("invalid event seq")
							return fmt.Errorf("invalid event seq")
						}
					}
					receipt.Events = events
				}
				if len(receipts) > 0 {
					msgCh <- &chain.Message{Receipts: receipts}
				}
				lastHeight++
				return nil
			}); err != nil {
			r.log.Errorf("receiveLoop terminated: %v", err)
			_errCh <- err
		}
	}()

	return _errCh, nil
}

func (r *receiver) getRelayReceipts(v *types.BlockNotification) []*chain.Receipt {
	sc := common.HexToAddress(r.src.ContractAddress())
	var receipts []*chain.Receipt
	var events []*chain.Event
	for i, receipt := range v.Receipts {
		events := events[:0]
		for _, log := range receipt.Logs {
			if !bytes.Equal(log.Address.Bytes(), sc.Bytes()) {
				continue
			}
			msg, err := r.client().ParseMessage(ethTypes.Log{
				Data: log.Data, Topics: log.Topics,
			})
			if err == nil && strings.EqualFold(msg.Next, r.dst.String()) {
				events = append(events, &chain.Event{
					Next:     chain.BTPAddress(msg.Next),
					Sequence: msg.Seq.Uint64(),
					Message:  msg.Msg,
				})
			}
		}
		if len(events) > 0 {
			rp := &chain.Receipt{}
			rp.Index, rp.Height = uint64(i), v.Height.Uint64()
			rp.Events = append(rp.Events, events...)
			receipts = append(receipts, rp)
		}
	}
	return receipts
}

func VerifierOptsSnapshot(opts *VerifierOptions) {
	data := map[string]interface{}{
		"blockHeight":          opts.BlockHeight,
		"justifiedBlockHeight": opts.JustifiedBlockHeight,
		"validatorData":        opts.ValidatorData.String(),
	}
	file, _ := json.MarshalIndent(data, "", " ")

	_ = ioutil.WriteFile("verifierOptsSnapshot.json", file, 0644)
}
