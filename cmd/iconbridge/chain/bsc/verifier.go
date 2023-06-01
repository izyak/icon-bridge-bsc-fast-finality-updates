package bsc

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"sync"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls"
	"github.com/willf/bitset"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	bscTypes "github.com/icon-project/icon-bridge/cmd/iconbridge/chain/bsc/types"
	"github.com/icon-project/icon-bridge/common"
	"github.com/icon-project/icon-bridge/common/log"
	"github.com/pkg/errors"
)

const (
	extraVanity        = 32          // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal          = 65          // Fixed number of extra-data suffix bytes reserved for signer seal
	defaultEpochLength = uint64(200) // Default number of blocks of checkpoint to update validatorSet from contract

	BLSPublicKeyLength              = 48
	validatorBytesLengthBeforeLuban = ethCommon.AddressLength
	validatorBytesLength            = ethCommon.AddressLength + BLSPublicKeyLength
	validatorNumberSize             = 1 // Fixed number of extra prefix bytes reserved for validator number after Luban

	ParliaGasLimitBoundDivisor uint64 = 256                // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit                uint64 = 5000               // Minimum the gas limit may ever be.
	MaxGasLimit                uint64 = 0x7fffffffffffffff // Maximum the gas limit (2^63-1).
)

var (
	big1       = big.NewInt(1)
	uncleHash  = types.CalcUncleHash(nil)
	LubanBlock = big.NewInt(29295050)
	PlatoBlock = big.NewInt(29861024)
)

var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	errMissingValidators = errors.New("epoch block does not have validators")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is missing.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")
)

type VerifierOptions struct {
	BlockHeight   uint64          `json:"blockHeight"`
	BlockHash     common.HexBytes `json:"parentHash"`
	ValidatorData common.HexBytes `json:"validatorData"`
}

// next points to height whose parentHash is expected
// parentHash of height h is got from next-1's hash
type Verifier struct {
	chainID                    *big.Int
	mu                         sync.RWMutex
	next                       *big.Int
	parentHash                 ethCommon.Hash
	validators                 map[ethCommon.Address]bool
	prevValidators             map[ethCommon.Address]bool
	blsPubKeys                 []bscTypes.BLSPublicKey
	useNewValidatorsFromHeight *big.Int
}

type IVerifier interface {
	Next() *big.Int
	Verify(header *types.Header, nextHeader *types.Header, receipts ethTypes.Receipts) error
	Update(header *types.Header) (err error)
	ParentHash() ethCommon.Hash
	IsValidator(addr ethCommon.Address, curHeight *big.Int) bool
}

func (vr *Verifier) Next() *big.Int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return (&big.Int{}).Set(vr.next)
}

func (vr *Verifier) ChainID() *big.Int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return (&big.Int{}).Set(vr.chainID)
}

func (vr *Verifier) ParentHash() ethCommon.Hash {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return ethCommon.BytesToHash(vr.parentHash.Bytes())
}

func (vr *Verifier) IsValidator(addr ethCommon.Address, curHeight *big.Int) bool {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	exists := false
	if curHeight.Cmp(vr.useNewValidatorsFromHeight) >= 0 {
		_, exists = vr.validators[addr]
	} else {
		_, exists = vr.prevValidators[addr]
	}

	return exists
}

// prove that header is linked to verified nextHeader
// only then can header be used for receiver.Callback or vr.Update()
func (vr *Verifier) Verify(header *types.Header, nextHeader *types.Header, receipts ethTypes.Receipts) error {

	if nextHeader.Number.Cmp((&big.Int{}).Add(header.Number, big1)) != 0 {
		return fmt.Errorf("Different height between successive header: Prev %v New %v", header.Number, nextHeader.Number)
	}
	if header.Hash() != nextHeader.ParentHash {
		return fmt.Errorf("Different hash between successive header: (%v): Prev %v New %v", header.Number, header.Hash(), nextHeader.ParentHash)
	}
	if vr.Next().Cmp(header.Number) != 0 {
		return fmt.Errorf("Unexpected height: Got %v Expected %v", header.Number, vr.Next())
	}
	if header.ParentHash != vr.ParentHash() {
		return fmt.Errorf("Unexpected Hash(%v): Got %v Expected %v", header.Number, header.ParentHash, vr.ParentHash())
	}

	if err := vr.verifyHeader(nextHeader); err != nil {
		return errors.Wrapf(err, "verifyHeader %v", err)
	}
	if err := vr.verifyCascadingFields(nextHeader, header); err != nil {
		return errors.Wrapf(err, "verifyCascadingFields %v", err)
	}
	// TODO: Fix as per incoming parms
	parents := []*types.Header{header}
	if err := vr.verifyVoteAttestation(nextHeader, parents); err != nil {
		log.Println("Warn: Error verifying vote attestation") // TODO: How does logging work for verifier.., only receiver has logs?
		if isPlatoBlock(header.Number) {                      // is plato block
			return err
		}
	}
	if err := vr.verifySeal(nextHeader, vr.ChainID()); err != nil {
		return errors.Wrapf(err, "verifySeal %v", err)
	}
	if len(receipts) > 0 {
		if err := vr.validateState(nextHeader, receipts); err != nil {
			return errors.Wrapf(err, "validateState %v", err)
		}
	}
	return nil
}

func (vr *Verifier) Update(header *types.Header) (err error) {
	// TODO: Add Parent header
	vr.mu.Lock()
	defer vr.mu.Unlock()
	if header.Number.Uint64()%defaultEpochLength == 0 {
		newValidators, valPubKeys, err := parseValidators(header)
		if err != nil {
			return errors.Wrapf(err, "getValidatorMapFromHex %v", err)
		}
		// update validators only if epoch block and no error encountered
		vr.prevValidators = vr.validators
		vr.validators = newValidators
		vr.blsPubKeys = valPubKeys
		vr.useNewValidatorsFromHeight = (&big.Int{}).Add(header.Number, big.NewInt(1+int64(len(vr.prevValidators)/2)))
	}
	vr.parentHash = header.Hash()
	vr.next.Add(header.Number, big1)
	return
}

func getValidatorMapFromHeightAndExtras(height uint64, headerExtra common.HexBytes) (map[ethCommon.Address]bool, error) {
	if len(headerExtra) < extraVanity+extraSeal {
		return nil, errMissingSignature
	}

	// valBytesLength to represent validatorBytesLength before or after luban
	currValBytesLength := validatorBytesLengthBeforeLuban
	if isLubanBlock(big.NewInt(int64(height))) {
		currValBytesLength = validatorBytesLength
	}

	addrs := getValidatorBytesFromExtrasAndHeight(height, headerExtra)
	numAddrs := len(addrs) / currValBytesLength
	newVals := make(map[ethCommon.Address]bool, numAddrs)
	for i := 0; i < numAddrs; i++ {
		newVals[ethCommon.BytesToAddress(addrs[i*currValBytesLength:(i+1)*currValBytesLength])] = true
	}
	return newVals, nil
}

func getValidatorBytesFromExtrasAndHeight(height uint64, headerExtra common.HexBytes) []byte {
	if len(headerExtra) <= extraVanity+extraSeal {
		return nil
	}

	if !isLubanBlock(big.NewInt(int64(height))) {
		if height%defaultEpochLength == 0 && (len(headerExtra)-extraSeal-extraVanity)%validatorBytesLengthBeforeLuban != 0 {
			return nil
		}
		return headerExtra[extraVanity : len(headerExtra)-extraSeal]
	}

	if height%defaultEpochLength != 0 {
		return nil
	}
	num := int(headerExtra[extraVanity])
	if num == 0 || len(headerExtra) <= extraVanity+extraSeal+num*validatorBytesLength {
		return nil
	}
	start := extraVanity + validatorNumberSize
	end := start + num*validatorBytesLength
	return headerExtra[start:end]
}

func isLubanBlock(height *big.Int) bool {
	return height.Cmp(LubanBlock) > 0
}

func isPlatoBlock(height *big.Int) bool {
	return height.Cmp(PlatoBlock) > 0
}

func parseValidators(header *ethTypes.Header) (map[ethCommon.Address]bool, []bscTypes.BLSPublicKey, error) {
	validatorsBytes := getValidatorBytesFromHeader(header)
	if len(validatorsBytes) == 0 {
		return nil, nil, errors.New("invalid validators bytes")
	}

	if !isLubanBlock(header.Number) {
		n := len(validatorsBytes) / validatorBytesLengthBeforeLuban
		// result := make([]ethCommon.Address, n)
		result := make(map[ethCommon.Address]bool, n)
		for i := 0; i < n; i++ {
			result[ethCommon.BytesToAddress(validatorsBytes[i*validatorBytesLengthBeforeLuban:(i+1)*validatorBytesLengthBeforeLuban])] = true
		}
		return result, nil, nil
	}

	n := len(validatorsBytes) / validatorBytesLength
	cnsAddrs := make(map[ethCommon.Address]bool, n)
	voteAddrs := make([]bscTypes.BLSPublicKey, n)

	for i := 0; i < n; i++ {
		valAddr := ethCommon.BytesToAddress(validatorsBytes[i*validatorBytesLength : i*validatorBytesLength+ethCommon.AddressLength])
		cnsAddrs[valAddr] = true
		copy(voteAddrs[i][:], validatorsBytes[i*validatorBytesLength+ethCommon.AddressLength:(i+1)*validatorBytesLength])
	}
	return cnsAddrs, voteAddrs, nil
}

// getValidatorBytesFromHeader returns the validators bytes extracted from the header's extra field if exists.
// The validators bytes would be contained only in the epoch block's header, and its each validator bytes length is fixed.
// On luban fork, we introduce vote attestation into the header's extra field, so extra format is different from before.
// Before luban fork: |---Extra Vanity---|---Validators Bytes (or Empty)---|---Extra Seal---|
// After luban fork:  |---Extra Vanity---|---Validators Number and Validators Bytes (or Empty)---|---Vote Attestation (or Empty)---|---Extra Seal---|
func getValidatorBytesFromHeader(header *ethTypes.Header) []byte {
	if len(header.Extra) <= extraVanity+extraSeal {
		return nil
	}

	if !isLubanBlock(header.Number) {
		if header.Number.Uint64()%defaultEpochLength == 0 && (len(header.Extra)-extraSeal-extraVanity)%validatorBytesLengthBeforeLuban != 0 {
			return nil
		}
		return header.Extra[extraVanity : len(header.Extra)-extraSeal]
	}

	if header.Number.Uint64()%defaultEpochLength != 0 {
		return nil
	}
	num := int(header.Extra[extraVanity])
	if num == 0 || len(header.Extra) <= extraVanity+extraSeal+num*validatorBytesLength {
		return nil
	}
	start := extraVanity + validatorNumberSize
	end := start + num*validatorBytesLength
	return header.Extra[start:end]
}

// getVoteAttestationFromHeader returns the vote attestation extracted from the header's extra field if exists.
func getVoteAttestationFromHeader(header *ethTypes.Header) (*bscTypes.VoteAttestation, error) {
	if len(header.Extra) <= extraVanity+extraSeal {
		return nil, nil
	}

	if !isLubanBlock(header.Number) {
		return nil, nil
	}

	var attestationBytes []byte
	if header.Number.Uint64()%defaultEpochLength != 0 {
		attestationBytes = header.Extra[extraVanity : len(header.Extra)-extraSeal]
	} else {
		num := int(header.Extra[extraVanity])
		if len(header.Extra) <= extraVanity+extraSeal+validatorNumberSize+num*validatorBytesLength {
			return nil, nil
		}
		start := extraVanity + validatorNumberSize + num*validatorBytesLength
		end := len(header.Extra) - extraSeal
		attestationBytes = header.Extra[start:end]
	}

	var attestation bscTypes.VoteAttestation
	if err := rlp.Decode(bytes.NewReader(attestationBytes), &attestation); err != nil {
		return nil, fmt.Errorf("block %d has vote attestation info, decode err: %s", header.Number.Uint64(), err)
	}
	return &attestation, nil
}

func (vr *Verifier) verifyHeader(header *types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	// if header.Time > uint64(time.Now().Unix()) {
	// 	return consensus.ErrFutureBlock
	// }
	// Check that the extra-data contains the vanity, validators and signature.
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// check extra data
	isEpoch := number%defaultEpochLength == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := getValidatorBytesFromHeader(header)
	if !isEpoch && len(signersBytes) != 0 {
		return errExtraValidators
	}

	// required ? not present on bsc repo
	if isEpoch && len(signersBytes) == 0 {
		return errMissingValidators
	}

	if isEpoch && len(signersBytes)%validatorBytesLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (ethCommon.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 && header.Difficulty == nil {
		return errInvalidDifficulty
	}
	return nil
}

func (vr *Verifier) verifyCascadingFields(header *types.Header, parent *types.Header) error {
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	// Verify that the gas limit is <= 2^63-1
	capacity := MaxGasLimit
	if header.GasLimit > capacity {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, capacity)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / ParliaGasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	return nil
}

func getJustifiedNumberAndHash(header *types.Header) (uint64, ethCommon.Hash, error) {
	if header == nil {
		return 0, ethCommon.Hash{}, fmt.Errorf("illegal chain or header")
	}
	parentAttestation, err := getVoteAttestationFromHeader(header)
	if err != nil {
		return 0, ethCommon.Hash{}, err
	}

	if parentAttestation == nil {
		if isLubanBlock(header.Number) {
			// TODO: how to handle logs?
			log.Debug("once one attestation generated, attestation of snap would not be nil forever basically")
		}
		// 6d3c... is hash of block 0 of BSC
		return 0, ethCommon.HexToHash("6d3c66c5357ec91d5c43af47e234a939b22557cbb552dc45bebbceeed90fbe34"), nil
	}

	return parentAttestation.Data.TargetNumber, parentAttestation.Data.TargetHash, nil
}

func (vr *Verifier) verifyVoteAttestation(header *ethTypes.Header, parents []*ethTypes.Header) error {

	attestation, err := getVoteAttestationFromHeader(header)
	if err != nil {
		return err
	}
	if attestation == nil {
		return nil
	}
	if attestation.Data == nil {
		return fmt.Errorf("invalid attestation, vote data is nil")
	}
	if len(attestation.Extra) > bscTypes.MaxAttestationExtraLength {
		return fmt.Errorf("invalid attestation, too large extra length: %d", len(attestation.Extra))
	}

	// Get parent block
	// number := header.Number.Uint64()
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		// queryHeader()
		// parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	// The target block should be direct parent.
	targetNumber := attestation.Data.TargetNumber
	targetHash := attestation.Data.TargetHash
	if targetNumber != parent.Number.Uint64() || targetHash != parent.Hash() {
		return fmt.Errorf("invalid attestation, target mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
			parent.Number.Uint64(), parent.Hash(), targetNumber, targetHash)
	}

	// The source block should be the highest justified block.
	sourceNumber := attestation.Data.SourceNumber
	sourceHash := attestation.Data.SourceHash
	justifiedBlockNumber, justifiedBlockHash, err := getJustifiedNumberAndHash(parent)

	if err != nil {
		return fmt.Errorf("unexpected error when getting the highest justified number and hash")
	}
	if sourceNumber != justifiedBlockNumber || sourceHash != justifiedBlockHash {
		return fmt.Errorf("invalid attestation, source mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
			justifiedBlockNumber, justifiedBlockHash, sourceNumber, sourceHash)
	}

	// The snapshot should be the targetNumber-1 block's snapshot.
	if len(parents) > 1 {
		parents = parents[:len(parents)-1]
	} else {
		parents = nil
	}

	validators := vr.validators
	blsPubKeys := vr.blsPubKeys
	if len(validators) != len(blsPubKeys) {
		return fmt.Errorf("Length of validators and bls public keys not same")
	}

	validatorsBitSet := bitset.From([]uint64{uint64(attestation.VoteAddressSet)})
	if validatorsBitSet.Count() > uint(len(validators)) {
		return fmt.Errorf("invalid attestation, vote number larger than validators number")
	}

	votedAddrs := make([]bls.PublicKey, 0, validatorsBitSet.Count())

	for index, value := range blsPubKeys {
		if !validatorsBitSet.Test(uint(index)) {
			continue
		}
		voteAddr, err := bls.PublicKeyFromBytes(value[:])
		if err != nil {
			return fmt.Errorf("BLS public key converts failed: %v", err)
		}
		votedAddrs = append(votedAddrs, voteAddr)
	}

	// The valid voted validators should be no less than 2/3 validators.
	if len(votedAddrs) < ceilDiv(len(validators)*2, 3) {
		return fmt.Errorf("invalid attestation, not enough validators voted")
	}

	// Verify the aggregated signature.
	aggSig, err := bls.SignatureFromBytes(attestation.AggSignature[:])
	if err != nil {
		return fmt.Errorf("BLS signature converts failed: %v", err)
	}
	if !aggSig.FastAggregateVerify(votedAddrs, attestation.Data.Hash()) {
		return fmt.Errorf("invalid attestation, signature verify failed")
	}

	return nil
}

func (vr *Verifier) verifySeal(header *types.Header, chainID *big.Int) error {
	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, chainID)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}

	if ok := vr.IsValidator(signer, header.Number); !ok {
		return errUnauthorizedValidator
	}
	// TODO: check if signer is a recent Validator; avoid recent validators for spam protection
	return nil
}

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, chainId *big.Int) (ethCommon.Address, error) {
	if len(header.Extra) < extraSeal {
		return ethCommon.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header, chainId).Bytes(), signature)
	if err != nil {
		return ethCommon.Address{}, err
	}
	var signer ethCommon.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, chainId *big.Int) (hash ethCommon.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header, chainId *big.Int) {
	err := rlp.Encode(w, []interface{}{
		chainId,
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // this will panic if extra is too short, should check before calling encodeSigHeader
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

func (vr *Verifier) validateState(header *types.Header, receipts types.Receipts) error {
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	receiptSha := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	return nil
}

func ceilDiv(x, y int) int {
	if y == 0 {
		return 0
	}
	return (x + y - 1) / y
}
