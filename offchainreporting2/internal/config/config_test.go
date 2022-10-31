package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/libocr/offchainreporting2/reportingplugin/median"
	"github.com/smartcontractkit/libocr/offchainreporting2/types"
)

func TestSetConfigArgs(t *testing.T) {

	offchainPubKeysHex := []string{
		"e4f74390c92847bae04aa635b76da2ba1fd395ccaa95292e252701b81c0de073",
		"2114b3af9318f7068ca9c18fef10486a6ea039da5c538b25ae88e6b19b08ba91",
		"0101b9cc83031f90ec9825c5b9c7cad7b69ee5534f0970d116fa5aac09f686b4",
		"0fed3dbef8ab39c10cb12a44e505a3a3192734afe52aab4c14cf1c91f848aff8"}

	configPublicKeys := []string{
		"de8649493568c530000cd7491d0e8a99f706f7e187f3788a23de41e5b410a101",
		"5149671107bc8f2b7345bf00c7c32c8c7bf0f566368daad7b3a5d233d9f93877",
		"eb6e0a2fda203488125e91da20220a5c0a0b09942c241a27c442e4f0e2b13e36",
		"55eadae1a4c68bfe149a15cccc39da81d12c82235c5bcc57edee19b85013d41f"}

	signingAddresses := []common.Address{
		common.HexToAddress("29ec20b6a1744f640464f15d1b33e346256aa239"),
		common.HexToAddress("d5cf88b7be7d9520c1365e385c635a3a66b7c0ff"),
		common.HexToAddress("b733ebc7cb2aa65782c3b4e9ec264d3291efe4cb"),
		common.HexToAddress("c0709d5b73e0e3e58c47e7ee5c66952ea7cf1930")}

	peerIDs := []string{
		"12D3KooWFZPKLnkGEaV14F9QcMzXZ1GMi7Btz3jwoWgfLr9W1Y98",
		"12D3KooWA7QVXdKezetynhgBjajQQBXheYGVjurNqrTRc1GUDx8m",
		"12D3KooWNXc2UT6CrniDxy4D2NXxeczSwhcZMDWb6BGpHP5h6uK1",
		"12D3KooWMDKwMCofVuYpzxMRBpA9XXYDYeye2T5guNeWeKiG6DK7",
	}

	transmiterAddresses := []string{
		"0x505f48A55e2b4DaC4C870124bc7b48E105513FF3",
		"0x8D9E975E95AE2f55CB6D0768e83f53430844541A",
		"0x7731e41F93b39B5ea97Fc400067e8A285493ddf7",
		"0x67Ef0866bFE419A1143e7094F9440748F32A2879",
	}

	offchainPubKeysBytes := []types.OffchainPublicKey{}
	for _, pkHex := range offchainPubKeysHex {
		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			t.Fatal(err)
		}

		pkBytesFixed := [ed25519.PublicKeySize]byte{}
		n := copy(pkBytesFixed[:], pkBytes)
		if n != ed25519.PublicKeySize {
			t.Fatal("wrong num elements copied")
		}

		offchainPubKeysBytes = append(offchainPubKeysBytes, types.OffchainPublicKey(pkBytesFixed))
	}

	configPubKeysBytes := []types.ConfigEncryptionPublicKey{}
	for _, pkHex := range configPublicKeys {
		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			t.Fatal(err)
		}

		pkBytesFixed := [ed25519.PublicKeySize]byte{}
		n := copy(pkBytesFixed[:], pkBytes)
		if n != ed25519.PublicKeySize {
			t.Fatal("wrong num elements copied")
		}

		configPubKeysBytes = append(configPubKeysBytes, types.ConfigEncryptionPublicKey(pkBytesFixed))
	}

	o := []OracleIdentityExtra{}

	for index := range configPublicKeys {
		o = append(o, OracleIdentityExtra{
			OracleIdentity: OracleIdentity{
				OnchainPublicKey:  signingAddresses[index][:],
				OffchainPublicKey: offchainPubKeysBytes[index],
				PeerID:            peerIDs[index],
				TransmitAccount:   types.Account(transmiterAddresses[index]),
			},
			ConfigEncryptionPublicKey: configPubKeysBytes[index],
		})
	}

	fmt.Println("MADE ORACLE IDENTITIES")
	fmt.Println(o)
	signers, transmitters, f, onchainConfig, offchainConfigVersion, offchainConfig, err := ContractSetConfigArgsForOnChain(
		o, 1, uint64(1000))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("signers:", signers)
	fmt.Println("transmitters:", transmitters)
	fmt.Println("f:", f)
	fmt.Println("onchainConfig:", onchainConfig)
	fmt.Println("offchainConfigVersion:", offchainConfigVersion)
	fmt.Println("offchainConfig:", hex.EncodeToString(offchainConfig))
	fmt.Println(err)
}

type OracleIdentityExtra struct {
	OracleIdentity
	ConfigEncryptionPublicKey types.ConfigEncryptionPublicKey
}

func ContractSetConfigArgsForOnChain(
	oracles []OracleIdentityExtra,
	f int,
	alphaPPB uint64,
) (
	signers []common.Address,
	transmitters []common.Address,
	f_ uint8,
	onchainConfig []byte,
	offchainConfigVersion uint64,
	offchainConfig []byte,
	err error,
) {
	S := []int{}
	identities := []OracleIdentity{}
	sharedSecretEncryptionPublicKeys := []types.ConfigEncryptionPublicKey{}
	for _, oracle := range oracles {
		S = append(S, 1)
		identities = append(identities, OracleIdentity{
			oracle.OffchainPublicKey,
			oracle.OnchainPublicKey,
			oracle.PeerID,
			oracle.TransmitAccount,
		})
		sharedSecretEncryptionPublicKeys = append(sharedSecretEncryptionPublicKeys, oracle.ConfigEncryptionPublicKey)
	}
	sharedConfig := SharedConfig{
		PublicConfig{
			30 * time.Second,
			10 * time.Second,
			10 * time.Second,
			20 * time.Second,
			20 * time.Second,
			3,
			S,
			identities,
			median.OffchainConfig{
				false,
				alphaPPB,
				false,
				alphaPPB,
				0,
			}.Encode(),
			5 * time.Second,
			5 * time.Second,
			5 * time.Second,
			5 * time.Second,
			5 * time.Second,
			f,
			nil, // The median reporting plugin has an empty onchain config
			types.ConfigDigest{},
		},
		&[SharedSecretSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8},
	}
	return XXXContractSetConfigArgsFromSharedConfigEthereum(sharedConfig, sharedSecretEncryptionPublicKeys)
}
