OTmining
---

This program mines new block one time.
Before running this program, You must check that bitcoind program with rpc server mode runs already.

```
OTmining ---getblocktemplate---> bitcoind(RPC)
         <------response--------
         |
         solve
         |
         ------submitblock----->
```

## Dependencies

### List

* libblkmaker: [commit 5e409f22fb](https://github.com/bitcoin/libblkmaker/tree/5e409f22fb03be81b9c60d36a2bb17fe2348fa6c))
* jansson: stable 2.7
* libgcrypt: stable 1.7.2
* curl(libcurl): stable 7.50.1

### Install

#### OSX

```
brew install curl
brew install libgcrypt
brew install jansson
git clone https://github.com/bitcoin/libbase58
git clone https://github.com/bitcoin/libblkmaker
```

## Compile

```
gcc main.c -lgcrypt -lblkmaker-0.1 -ljansson -lblkmaker_jansson-0.1 -lcurl
```