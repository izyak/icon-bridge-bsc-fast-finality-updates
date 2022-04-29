package hmny

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/harmony-one/harmony/core/types"
	"github.com/icon-project/btp/cmd/btpsimple/chain"
	"github.com/icon-project/btp/common/errors"
	"github.com/icon-project/btp/common/log"
)

const (
	defaultReadTimeout         = 15 * time.Second
	monitorBlockMaxConcurrency = 1000 // number of concurrent requests to synchronize older blocks from source chain
)

func NewReceiver(
	src, dst chain.BTPAddress, urls []string,
	opts map[string]interface{}, l log.Logger) (chain.Receiver, error) {
	r := &receiver{
		log: l,
		src: src,
		dst: dst,
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("empty urls: %v", urls)
	}
	err := r.opts.Unmarshal(opts)
	if err != nil {
		return nil, err
	}
	r.cls, err = newClients(urls, src.ContractAddress(), r.log)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type receiverOptions struct {
	Verifier *VerifierOptions `json:"verifier"`
}

func (opts *receiverOptions) Unmarshal(v map[string]interface{}) error {
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
	opts receiverOptions
	cls  []*client
}

func (r *receiver) client() *client {
	return r.cls[rand.Intn(len(r.cls))]
}

func (r *receiver) rpcConsensusCall(
	threshold float64,
	method string,
	valfn func() interface{},
	keyfn func(val interface{}) interface{},
	args ...interface{}) (interface{}, error) {

	ctx, cancel := context.WithTimeout(context.Background(), defaultReadTimeout)
	defer cancel()

	if threshold == 0 {
		val := valfn()
		err := r.client().rpc.CallContext(ctx, val, method, args...)
		if err != nil {
			return nil, err
		}
		return val, nil
	}

	total := len(r.cls)

	ech := make(chan error, total)
	vch := make(chan interface{}, total)
	for _, caller := range r.cls {
		go func(clr *rpc.Client) {
			val := valfn()
			err := clr.CallContext(ctx, val, method, args...)
			if err != nil {
				val = nil
			}
			ech <- err
			vch <- val
		}(caller.rpc)
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

// Options for a new block notifications channel
type bnOptions struct {
	StartHeight     uint64
	Concurrency     uint64
	VerifierOptions *VerifierOptions
}

func (r *receiver) receiveLoop(ctx context.Context, opts *bnOptions, callback func(v *BlockNotification) error) error {

	if opts == nil {
		return errors.New("receiveLoop: invalid options: <nil>")
	}

	if opts.Concurrency < 1 || opts.Concurrency > monitorBlockMaxConcurrency {
		concurrency := opts.Concurrency
		if concurrency < 1 {
			opts.Concurrency = 1
		} else {
			opts.Concurrency = monitorBlockMaxConcurrency
		}
		r.log.Warnf("receiveLoop: opts.Concurrency (%d): value out of range [%d, %d]: setting to default %d",
			concurrency, 1, monitorBlockMaxConcurrency, opts.Concurrency)
	}

	if opts.VerifierOptions != nil &&
		opts.StartHeight < opts.VerifierOptions.BlockHeight {
		return fmt.Errorf(
			"receiveLoop: start height (%d) < verifier height (%d)",
			opts.StartHeight, opts.VerifierOptions.BlockHeight,
		)
	}
	vr, err := r.client().newVerifier(opts.VerifierOptions)
	if err != nil {
		return errors.Wrapf(err, "receiveLoop: NewVerifier: %v", err)
	}
	if err = r.client().syncVerifier(vr, opts.StartHeight); err != nil {
		return errors.Wrapf(err, "receiveLoop: cl.syncVerifier: %v", err)
	}

	// block notification channel
	// (buffered: to avoid deadlock)
	// increase concurrency parameter for faster sync
	bnch := make(chan *BlockNotification, opts.Concurrency)

	latest, next := uint64(0), opts.StartHeight

	heightPoller := time.NewTicker(time.Second)
	defer heightPoller.Stop()

	// last unverified block notification
	var lbn *BlockNotification

	// start monitor loop
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-heightPoller.C:
			height, err := r.client().GetBlockNumber()
			if err != nil {
				r.log.WithFields(log.Fields{"error": err}).Error("receiveLoop: failed to GetBlockNumber")
				continue
			}
			if height <= latest {
				continue
			}
			latest = height
			if next > latest {
				r.log.Debugf("receiveLoop: skipping; latest=%d, next=%d", latest, next)
			}

		case bn := <-bnch:
			// process all notifications
			for ; bn != nil; next++ {
				if lbn != nil {
					ok, err := vr.Verify(lbn.Header,
						bn.Header.LastCommitBitmap, bn.Header.LastCommitSignature)
					if err != nil {
						r.log.Errorf("receiveLoop: signature validation failed: h=%d, %v", lbn.Header.Number, err)
						break
					}
					if !ok {
						r.log.Errorf("receiveLoop: invalid header: signature validation failed: h=%d", lbn.Header.Number)
						break
					}
					if err := vr.Update(lbn.Header); err != nil {
						return errors.Wrapf(err, "receiveLoop: update verifier: %v", err)
					}
					if err := callback(lbn); err != nil {
						return errors.Wrapf(err, "receiveLoop: callback: %v", err)
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
				h     uint64
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
				case q.err != nil:
					if q.retry > 0 {
						q.retry--
						q.v, q.err = nil, nil
						qch <- q
					} else {
						r.log.Errorf("receiveLoop: bnq: h=%d:%v, %v", q.h, q.v.Header.Hash(), q.err)
						bns = append(bns, nil)
						if len(bns) == cap(bns) {
							close(qch)
						}
					}
				case q.v != nil:
					bns = append(bns, q.v)
					if len(bns) == cap(bns) {
						close(qch)
					}
				default:
					go func(q *bnq) {
						defer func() { qch <- q }()
						if q.v == nil {
							q.v = &BlockNotification{}
						}
						q.v.Height = (&big.Int{}).SetUint64(q.h)
						q.v.Header, q.err = r.client().GetHmyHeaderByHeight(q.v.Height)
						if q.err != nil {
							q.err = errors.Wrapf(q.err, "GetHmyHeaderByHeight: %v", q.err)
							return
						}
						q.v.Hash = q.v.Header.Hash()
						if q.v.Header.GasUsed > 0 {
							q.v.Receipts, q.err = r.client().GetBlockReceipts(q.v.Hash)
							if q.err == nil {
								receiptsRoot := types.DeriveSha(q.v.Receipts)
								if !bytes.Equal(receiptsRoot.Bytes(), q.v.Header.ReceiptsRoot.Bytes()) {
									q.err = fmt.Errorf(
										"invalid receipts: remote=%v, local=%v",
										q.v.Header.ReceiptsRoot, receiptsRoot)
								}
							}
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

func (r *receiver) getRelayReceipts(v *BlockNotification) []*chain.Receipt {
	sc := common.HexToAddress(r.src.ContractAddress())
	var receipts []*chain.Receipt
	var events []*chain.Event
	for i, receipt := range v.Receipts {
		events := events[:0]
		for _, log := range receipt.Logs {
			if !bytes.Equal(log.Address.Bytes(), sc.Bytes()) {
				continue
			}
			msg, err := r.client().bmc.ParseMessage(ethtypes.Log{
				Data: log.Data, Topics: log.Topics,
			})
			if err == nil {
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
			r.log.Debugf("received event: h=%d: sc=%v", rp.Height, sc)
		}
	}
	return receipts
}

func (r *receiver) SubscribeMessage(ctx context.Context, height, seq uint64) (<-chan *chain.Message, error) {
	ch := make(chan *chain.Message)
	go func() {
		defer close(ch)
		lastHeight := height - 1
		if err := r.receiveLoop(ctx,
			&bnOptions{
				StartHeight:     height,
				VerifierOptions: r.opts.Verifier,
				Concurrency:     100,
			},
			func(v *BlockNotification) error {
				r.log.WithFields(log.Fields{"height": v.Height}).Debug("block notification")

				if v.Height.Uint64() != lastHeight+1 {
					r.log.Errorf("expected v.Height == %d, got %d", lastHeight+1, v.Height.Uint64())
					return fmt.Errorf(
						"block notification: expected=%d, got=%d",
						lastHeight+1, v.Height.Uint64())
				}

				receipts := r.getRelayReceipts(v)
				for _, receipt := range receipts {
					for _, event := range receipt.Events {
						seq++
						if event.Sequence > seq {
							r.log.WithFields(log.Fields{
								"seq": log.Fields{"got": event.Sequence, "expected": seq},
							}).Error("invalid event: cannot match seq")
							return fmt.Errorf("")
						}
					}
				}

				ch <- &chain.Message{Receipts: receipts}
				lastHeight++
				return nil
			}); err != nil {
			// TODO decide whether to ignore or handle err
			r.log.Errorf("receiveLoop terminated: %v", err)
		}
	}()
	return ch, nil
}
