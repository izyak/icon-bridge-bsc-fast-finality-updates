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
	uncleHash  = ethTypes.CalcUncleHash(nil)
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
	BlockHeight          uint64          `json:"blockHeight"`
	FinalizedBlockHeight uint64          `json:"finalizedBlockHeight"`
	ValidatorData        common.HexBytes `json:"validatorData"`
	SnapshotDir          string          `json:"snapshotDir"`
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
	useNewValidatorsFromHeight *big.Int
	latestJustifiedHeader      *ethTypes.Header
	blsPubKeys                 []bscTypes.BLSPublicKey
	prevBlsPubKeys             []bscTypes.BLSPublicKey
	log                        log.Logger
}

type IVerifier interface {
	Next() *big.Int
	Verify(lastHeader, currentHeader *ethTypes.Header, receipts ethTypes.Receipts) (error, bool)
	Update(justifiedHeader, currentHeader *ethTypes.Header) (err error)
	ParentHash() ethCommon.Hash
	IsValidator(addr ethCommon.Address, curHeight *big.Int) bool
	GetBlsPublicKeysForHeight(curHeight *big.Int) (map[ethCommon.Address]bool, []bscTypes.BLSPublicKey)
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

func (vr *Verifier) GetBlsPublicKeysForHeight(curHeight *big.Int) (map[ethCommon.Address]bool, []bscTypes.BLSPublicKey) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	if curHeight.Cmp(vr.useNewValidatorsFromHeight) >= 0 {
		return vr.validators, vr.blsPubKeys
	}
	return vr.prevValidators, vr.prevBlsPubKeys
}

// prove that header is linked to verified nextHeader
// only then can header be used for receiver.Callback or vr.Update()
func (vr *Verifier) Verify(lastHeader, currentHeader *ethTypes.Header, receipts ethTypes.Receipts) (error, bool) { // remove previous header

	if currentHeader.Number.Cmp((&big.Int{}).Add(lastHeader.Number, big1)) != 0 {
		return fmt.Errorf("different height between successive header: Prev %v New %v", lastHeader.Number, currentHeader.Number), false
	}
	if lastHeader.Hash() != currentHeader.ParentHash {
		return fmt.Errorf("different hash between successive header: (%v): Prev %v New %v", lastHeader.Number, lastHeader.Hash(), currentHeader.ParentHash), false
	}
	if vr.Next().Cmp(lastHeader.Number) != 0 {
		return fmt.Errorf("unexpected height: Got %v Expected %v", lastHeader.Number, vr.Next()), false
	}
	if lastHeader.ParentHash != vr.ParentHash() {
		return fmt.Errorf("unexpected Hash(%v): Got %v Expected %v", lastHeader.Number, lastHeader.ParentHash, vr.ParentHash()), false
	}

	if err := vr.verifyHeader(currentHeader); err != nil {
		return errors.Wrapf(err, "verifyHeader %v", err), false
	}
	if err := vr.verifyCascadingFields(currentHeader, lastHeader); err != nil {
		return errors.Wrapf(err, "verifyCascadingFields %v", err), false
	}
	if err := vr.verifySeal(currentHeader, vr.ChainID()); err != nil {
		return errors.Wrapf(err, "verifySeal %v", err), false
	}
	if len(receipts) > 0 {
		if err := vr.validateState(currentHeader, receipts); err != nil {
			return errors.Wrapf(err, "validateState %v", err), false
		}
	}
	var isVerified bool
	var err error
	if isLubanBlock(lastHeader.Number) {
		err, isVerified = vr.verifyVoteAttestation(currentHeader, lastHeader)
		if err != nil {
			vr.log.WithFields(log.Fields{"parentHeight": lastHeader.Number.String(), "currentHeight": currentHeader.Number.String()}).Warn("Verify vote attestation failed")
			if isPlatoBlock(lastHeader.Number) {
				return err, false
			}
		}

		if !isVerified {
			return nil, false
		}

	}

	return nil, true
}

func (vr *Verifier) Update(justifiedHeader, currentHeader *ethTypes.Header) (err error) {
	vr.mu.Lock()
	defer vr.mu.Unlock()
	if currentHeader.Number.Uint64()%defaultEpochLength == 0 {
		newValidators, valPubKeys, err := parseValidators(currentHeader)
		if err != nil {
			return errors.Wrapf(err, "getValidatorMapFromHex %v", err)
		}
		// update validators only if epoch block and no error encountered
		vr.prevValidators = vr.validators
		vr.validators = newValidators
		vr.prevBlsPubKeys = vr.blsPubKeys
		vr.blsPubKeys = valPubKeys
		vr.useNewValidatorsFromHeight = (&big.Int{}).Add(currentHeader.Number, big.NewInt(1+int64(len(vr.prevValidators)/2)))
	}
	vr.parentHash = currentHeader.ParentHash
	vr.next = currentHeader.Number
	vr.latestJustifiedHeader = justifiedHeader
	return
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
		cnsAddrs := make(map[ethCommon.Address]bool, n)
		for i := 0; i < n; i++ {
			cnsAddrs[ethCommon.BytesToAddress(validatorsBytes[i*validatorBytesLengthBeforeLuban:(i+1)*validatorBytesLengthBeforeLuban])] = true
		}
		return cnsAddrs, nil, nil
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

func (vr *Verifier) verifyHeader(header *ethTypes.Header) error {
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

	if isEpoch && len(signersBytes) == 0 {
		return errMissingValidators
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

func (vr *Verifier) verifyCascadingFields(header, parent *ethTypes.Header) error {
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

func (vr *Verifier) verifyVoteAttestation(header *ethTypes.Header, parent *ethTypes.Header) (error, bool) {
	attestation, err := getVoteAttestationFromHeader(header)
	if err != nil {
		return err, false
	}

	if parent == nil || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor, false
	}

	if attestation == nil {
		return nil, false
	}

	if attestation.Data == nil {
		return fmt.Errorf("invalid attestation, vote data is nil"), false
	}
	if len(attestation.Extra) > bscTypes.MaxAttestationExtraLength {
		return fmt.Errorf("invalid attestation, too large extra length: %d", len(attestation.Extra)), false
	}

	// The target block should be direct parent.
	targetNumber := attestation.Data.TargetNumber
	targetHash := attestation.Data.TargetHash
	if targetNumber != parent.Number.Uint64() || targetHash != parent.Hash() {
		return fmt.Errorf("invalid attestation, target mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
			parent.Number.Uint64(), parent.Hash(), targetNumber, targetHash), false
	}

	if vr.latestJustifiedHeader != nil {
		// The source block should be the highest justified block.
		sourceNumber := attestation.Data.SourceNumber
		sourceHash := attestation.Data.SourceHash
		justifiedBlockNumber, justifiedBlockHash := vr.latestJustifiedHeader.Number.Uint64(), vr.latestJustifiedHeader.Hash()

		if sourceNumber != justifiedBlockNumber || sourceHash != justifiedBlockHash {
			return fmt.Errorf("invalid attestation, source mismatch, expected block: %d, hash: %s; real block: %d, hash: %s",
				justifiedBlockNumber, justifiedBlockHash, sourceNumber, sourceHash), false
		}
	}

	validators, blsPubKeys := vr.GetBlsPublicKeysForHeight(parent.Number)
	if len(validators) != len(blsPubKeys) {
		return fmt.Errorf("length of validators and bls public keys not same"), false
	}

	validatorsBitSet := bitset.From([]uint64{uint64(attestation.VoteAddressSet)})
	if validatorsBitSet.Count() > uint(len(validators)) {
		return fmt.Errorf("invalid attestation, vote number larger than validators number"), false
	}

	votedAddrs := make([]bls.PublicKey, 0, validatorsBitSet.Count())

	for index, value := range blsPubKeys {
		if !validatorsBitSet.Test(uint(index)) {
			continue
		}
		voteAddr, err := bls.PublicKeyFromBytes(value[:])
		if err != nil {
			return fmt.Errorf("BLS public key converts failed: %v", err), false
		}
		votedAddrs = append(votedAddrs, voteAddr)
	}

	// The valid voted validators should be no less than 2/3 validators.
	if len(votedAddrs) < ceilDiv(len(validators)*2, 3) {
		return fmt.Errorf("invalid attestation, not enough validators voted"), false
	}

	// Verify the aggregated signature.
	aggSig, err := bls.SignatureFromBytes(attestation.AggSignature[:])
	if err != nil {
		return fmt.Errorf("BLS signature converts failed: %v", err), false
	}
	if !aggSig.FastAggregateVerify(votedAddrs, attestation.Data.Hash()) {
		return fmt.Errorf("invalid attestation, signature verify failed"), false
	}

	return nil, true
}

func (vr *Verifier) verifySeal(header *ethTypes.Header, chainID *big.Int) error {
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
func ecrecover(header *ethTypes.Header, chainId *big.Int) (ethCommon.Address, error) {
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
func SealHash(header *ethTypes.Header, chainId *big.Int) (hash ethCommon.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header, chainId)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *ethTypes.Header, chainId *big.Int) {
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

func (vr *Verifier) validateState(header *ethTypes.Header, receipts ethTypes.Receipts) error {
	rbloom := ethTypes.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	receiptSha := ethTypes.DeriveSha(receipts, trie.NewStackTrie(nil))
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
