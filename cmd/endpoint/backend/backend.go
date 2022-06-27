package backend

import (
	"context"

	"github.com/icon-project/icon-bridge/common/log"

	capi "github.com/icon-project/icon-bridge/cmd/endpoint/chainAPI"
	"github.com/icon-project/icon-bridge/cmd/endpoint/chainAPI/chain"
	wtchr "github.com/icon-project/icon-bridge/cmd/endpoint/watcher"
)

type backend struct {
	log      log.Logger
	chainapi capi.ChainAPI
	wtch     wtchr.Watcher
}

type Backend interface {
	Start(ctx context.Context) error
}

func New(l log.Logger, configPerChain map[chain.ChainType]*chain.ChainConfig) (Backend, error) {
	var err error
	be := &backend{log: l}
	be.chainapi, err = capi.New(l, configPerChain)
	if err != nil {
		return nil, err
	}
	be.wtch, err = wtchr.New(l, be.chainapi.SubEventChan(), be.chainapi.ErrChan())
	if err != nil {
		return nil, err
	}
	return be, nil
}

func (be *backend) Start(ctx context.Context) (err error) {
	if err = be.wtch.Start(ctx); err != nil {
		return
	}
	if err = be.chainapi.StartSubscription(ctx); err != nil {
		return
	}
	return
}

// m := map[ctr.ContractName]string{
// 	ctr.TokenIcon:         "cx7d6b69d7d2ff03379fa20765d533fb8355285dd3",
// 	ctr.NativeIcon:        "cxee3c4a5474bc9e722b7b5f34e99f56bf84bccf0f",
// 	ctr.Irc2Icon:          "cx491ef761730849efd43074692fb344c9bfab7f85",
// 	ctr.Irc2TradeableIcon: "cx3e08ab9fdb57a2688d8fec2f6c992bafb86b64e0",
// 	ctr.BmcIcon:           "cx0da2a6e1c7a1a026e50a21a536de922a45e7ecff",
// 	ctr.TokenHmy:          "0x8283e3bE7ac5f6dB332Df605f20E2B4c9977c662",
// 	ctr.NativeHmy:         "0xfad748a1063a40FF447B5D766331904d9bedDC26",
// 	ctr.Erc20Hmy:          "0xb54f5e97972AcF96470e02BE0456c8DB2173f33a",
// 	ctr.Erc20TradeableHmy: "0xefdc9E85d3FDbe52abe1af44c5d16dE1BB385DCa",
// 	ctr.BmcHmy:            "0x7a6DF2a2CC67B38E52d2340BF2BDC7c9a32AaE91",
// 	ctr.OwnerNativeHmy:    "0x05AcF27495FAAf9A178e316B9Da2f330983b9B95",
// 	ctr.OwnerTokenHmy:     "0x48cacC89f023f318B4289A18aBEd44753a127782",
// }
// be.dec, err = decoder.New("http://127.0.0.1:9500", m)
// if err != nil {
// 	return nil, err
// }