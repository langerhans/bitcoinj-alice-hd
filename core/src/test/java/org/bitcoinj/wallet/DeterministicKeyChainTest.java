/**
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.bitcoinj.wallet;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicHierarchy;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.UnreadableWalletException;
import org.bitcoinj.utils.Threading;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class DeterministicKeyChainTest {
    private static final Logger log = LoggerFactory.getLogger(DeterministicKeyChainTest.class);

    private DeterministicKeyChain chain;
    private final byte[] ENTROPY = Sha256Hash.create("don't use a string seed like this in real life".getBytes()).getBytes();

    private static final String TREZOR_SEED_PHRASE = "sniff divert demise scrub pony motor struggle innocent model mask enroll settle cash junior denial harsh peasant update estate aspect lyrics season empower asset";

    // m/44'/0'/0'/0/0
    private static final String EXPECTED_ADDRESS_0 = "1MkTpZN4TpLwJjZt9zHBXREJA8avUHXB3q";

    // m/44'/0'/0'/0/1
    private static final String EXPECTED_ADDRESS_1 = "1WGmwv86m1fFNVDRQ2YagdAFCButd36SV";

    // m/44'/0'/0'/0/2
    private static final String EXPECTED_ADDRESS_2 = "1PP1BvDeXjUcPDiEHBPWptQBAukhAwsLFt";

    // m/44'/0'/0'/0/3
    private static final String EXPECTED_ADDRESS_3 = "128f69V7GRqNSKwrjMkcuB6dbFKKEPtaLC";

    // m/44'/0'/0'/0/4
    private static final String EXPECTED_ADDRESS_4 = "18dxk72otf2amyAsjiKnEWhox5CJGQHYGA";

    //  The secs constant comes from the unit test file, so we can compare serialized data properly.
    private long secs = 1389353062L;

    NetworkParameters mainnet = NetworkParameters.fromID(NetworkParameters.ID_MAINNET);


    @Before
    public void setup() {
        //BriefLogFormatter.init();

        // You should use a random seed instead.
        chain = new DeterministicKeyChain(ENTROPY, "", secs);
        chain.setLookaheadSize(10);
        assertEquals(secs, checkNotNull(chain.getSeed()).getCreationTimeSeconds());
    }

    @Test
    public void derive() throws Exception {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        final Address address = new Address(UnitTestParams.get(), "n1bQNoEx8uhmCzzA5JPG6sFdtsUQhwiQJV");
        assertEquals(address, key1.toAddress(UnitTestParams.get()));
        assertEquals("mnHUcqUVvrfi5kAaXJDQzBb9HsWs78b42R", key2.toAddress(UnitTestParams.get()).toString());
        assertEquals(key1, chain.findKeyFromPubHash(address.getHash160()));
        assertEquals(key2, chain.findKeyFromPubKey(key2.getPubKey()));

        key1.sign(Sha256Hash.ZERO_HASH);

        ECKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals("mqumHgVDqNzuXNrszBmi7A2UpmwaPMx4HQ", key3.toAddress(UnitTestParams.get()).toString());
        key3.sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void getKeys() throws Exception {
        chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        chain.getKey(KeyChain.KeyPurpose.CHANGE);
        chain.maybeLookAhead();
        assertEquals(2, chain.getKeys(false).size());
    }

    @Test
    public void signMessage() throws Exception {
        ECKey key = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        key.verifyMessage("test", key.signMessage("test"));
    }

    @Test
    public void events() throws Exception {
        // Check that we get the right events at the right time.
        final List<List<ECKey>> listenerKeys = Lists.newArrayList();
        chain = new DeterministicKeyChain(ENTROPY, "", secs);
        chain.addEventListener(new AbstractKeyChainEventListener() {
            @Override
            public void onKeysAdded(List<ECKey> keys) {
                listenerKeys.add(keys);
            }
        }, Threading.SAME_THREAD);
        assertEquals(0, listenerKeys.size());
        chain.setLookaheadSize(5);
        assertEquals(0, listenerKeys.size());
        ECKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(1, listenerKeys.size());  // 1 event
        final List<ECKey> firstEvent = listenerKeys.get(0);
        assertEquals(1, firstEvent.size());
        assertTrue(firstEvent.contains(key));   // order is not specified.
        listenerKeys.clear();

        chain.maybeLookAhead();
        final List<ECKey> secondEvent = listenerKeys.get(0);
        assertEquals(12, secondEvent.size());  // (5 lookahead keys, +1 lookahead threshold) * 2 chains
        listenerKeys.clear();

        chain.getKey(KeyChain.KeyPurpose.CHANGE);
        // At this point we've entered the threshold zone so more keys won't immediately trigger more generations.
        assertEquals(0, listenerKeys.size());  // 1 event
        final int lookaheadThreshold = chain.getLookaheadThreshold() + chain.getLookaheadSize();
        for (int i = 0; i < lookaheadThreshold; i++)
            chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(1, listenerKeys.size());  // 1 event
        assertEquals(1, listenerKeys.get(0).size());  // 1 key.
    }

    @Test
    public void random() {
        // Can't test much here but verify the constructor worked and the class is functional. The other tests rely on
        // a fixed seed to be deterministic.
        chain = new DeterministicKeyChain(new SecureRandom(), 384);
        chain.setLookaheadSize(10);
        chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).sign(Sha256Hash.ZERO_HASH);
        chain.getKey(KeyChain.KeyPurpose.CHANGE).sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void serializeUnencrypted() throws UnreadableWalletException {
        chain.maybeLookAhead();
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        List<Protos.Key> keys = chain.serializeToProtobuf();
        // 1 mnemonic/seed, 1 master key, 1 account key, 2 internal keys, 3 derived, 20 lookahead and 5 lookahead threshold.
        int numItems =
                1  // mnemonic/seed
              + 1  // master key
              + 1  // account key
              + 2  // ext/int parent keys
              + (chain.getLookaheadSize() + chain.getLookaheadThreshold()) * 2   // lookahead zone on each chain
        ;
        assertEquals(numItems, keys.size());

        // Get another key that will be lost during round-tripping, to ensure we can derive it again.
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        final String EXPECTED_SERIALIZATION = checkSerialization(keys, "deterministic-wallet-serialization.txt");

        // Round trip the data back and forth to check it is preserved.
        int oldLookaheadSize = chain.getLookaheadSize();
        chain = DeterministicKeyChain.fromProtobuf(keys, null).get(0);
        // ALICE
        // assertEquals(EXPECTED_SERIALIZATION, protoToString(chain.serializeToProtobuf()));
        assertEquals(key1, chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, chain.findKeyFromPubHash(key2.getPubKeyHash()));
        assertEquals(key3, chain.findKeyFromPubHash(key3.getPubKeyHash()));
        assertEquals(key4, chain.getKey(KeyChain.KeyPurpose.CHANGE));
        key1.sign(Sha256Hash.ZERO_HASH);
        key2.sign(Sha256Hash.ZERO_HASH);
        key3.sign(Sha256Hash.ZERO_HASH);
        key4.sign(Sha256Hash.ZERO_HASH);
        assertEquals(oldLookaheadSize, chain.getLookaheadSize());
    }

    @Test(expected = IllegalStateException.class)
    public void notEncrypted() {
        chain.toDecrypted("fail");
    }

    @Test(expected = IllegalStateException.class)
    public void encryptTwice() {
        chain = chain.toEncrypted("once");
        chain = chain.toEncrypted("twice");
    }

    private void checkEncryptedKeyChain(DeterministicKeyChain encChain, DeterministicKey key1) {
        // Check we can look keys up and extend the chain without the AES key being provided.
        DeterministicKey encKey1 = encChain.findKeyFromPubKey(key1.getPubKey());
        DeterministicKey encKey2 = encChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertFalse(key1.isEncrypted());
        assertTrue(encKey1.isEncrypted());
        assertEquals(encKey1.getPubKeyPoint(), key1.getPubKeyPoint());
        final KeyParameter aesKey = checkNotNull(encChain.getKeyCrypter()).deriveKey("open secret");
        encKey1.sign(Sha256Hash.ZERO_HASH, aesKey);
        encKey2.sign(Sha256Hash.ZERO_HASH, aesKey);
        assertTrue(encChain.checkAESKey(aesKey));
        assertFalse(encChain.checkPassword("access denied"));
        assertTrue(encChain.checkPassword("open secret"));
    }

    @Test
    public void encryption() throws UnreadableWalletException {
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKeyChain encChain = chain.toEncrypted("open secret");
        DeterministicKey encKey1 = encChain.findKeyFromPubKey(key1.getPubKey());
        checkEncryptedKeyChain(encChain, key1);

        // Round-trip to ensure de/serialization works and that we can store two chains and they both deserialize.
        List<Protos.Key> serialized = encChain.serializeToProtobuf();
        List<Protos.Key> doubled = Lists.newArrayListWithExpectedSize(serialized.size() * 2);
        doubled.addAll(serialized);
        doubled.addAll(serialized);
        final List<DeterministicKeyChain> chains = DeterministicKeyChain.fromProtobuf(doubled, encChain.getKeyCrypter());
        assertEquals(2, chains.size());
        encChain = chains.get(0);
        checkEncryptedKeyChain(encChain, chain.findKeyFromPubKey(key1.getPubKey()));
        encChain = chains.get(1);
        checkEncryptedKeyChain(encChain, chain.findKeyFromPubKey(key1.getPubKey()));

        DeterministicKey encKey2 = encChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        // Decrypt and check the keys match.
        DeterministicKeyChain decChain = encChain.toDecrypted("open secret");
        DeterministicKey decKey1 = decChain.findKeyFromPubHash(encKey1.getPubKeyHash());
        DeterministicKey decKey2 = decChain.findKeyFromPubHash(encKey2.getPubKeyHash());
        assertEquals(decKey1.getPubKeyPoint(), encKey1.getPubKeyPoint());
        assertEquals(decKey2.getPubKeyPoint(), encKey2.getPubKeyPoint());
        assertFalse(decKey1.isEncrypted());
        assertFalse(decKey2.isEncrypted());
        assertNotEquals(encKey1.getParent(), decKey1.getParent());   // parts of a different hierarchy
        // Check we can once again derive keys from the decrypted chain.
        decChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).sign(Sha256Hash.ZERO_HASH);
        decChain.getKey(KeyChain.KeyPurpose.CHANGE).sign(Sha256Hash.ZERO_HASH);
    }

    @Test
    public void watchingChain() throws UnreadableWalletException {
        Utils.setMockClock();
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key3 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        DeterministicKey key4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);

        NetworkParameters params = MainNetParams.get();
        DeterministicKey watchingKey = chain.getWatchingKey();
        final String pub58 = watchingKey.serializePubB58(params);
        assertEquals("xpub69KR9epSNBM59KLuasxMU5CyKytMJjBP5HEZ5p8YoGUCpM6cM9hqxB9DDPCpUUtqmw5duTckvPfwpoWGQUFPmRLpxs5jYiTf2u6xRMcdhDf", pub58);
        watchingKey = DeterministicKey.deserializeB58(null, pub58, params);
        watchingKey.setCreationTimeSeconds(100000);
        chain = DeterministicKeyChain.watch(watchingKey);
        assertEquals(DeterministicHierarchy.BIP32_STANDARDISATION_TIME_SECS, chain.getEarliestKeyCreationTime());
        chain.setLookaheadSize(10);
        chain.maybeLookAhead();

        assertEquals(key1.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        assertEquals(key2.getPubKeyPoint(), chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS).getPubKeyPoint());
        final DeterministicKey key = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key3.getPubKeyPoint(), key.getPubKeyPoint());
        try {
            // Can't sign with a key from a watching chain.
            key.sign(Sha256Hash.ZERO_HASH);
            fail();
        } catch (ECKey.MissingPrivateKeyException e) {
            // Ignored.
        }
        // Test we can serialize and deserialize a watching chain OK.
        List<Protos.Key> serialization = chain.serializeToProtobuf();
        checkSerialization(serialization, "watching-wallet-serialization.txt");
        chain = DeterministicKeyChain.fromProtobuf(serialization, null).get(0);
        final DeterministicKey rekey4 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertEquals(key4.getPubKeyPoint(), rekey4.getPubKeyPoint());
    }

  /**
   * Test that a chain can be created for an account other than the HD account 0 of the BIP32 spec.
   * In this test a chain pointing to account 44 is created and some addresses tested.
   * This is a BIP44/ Trezor compatible chain. See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
   *
   * In this test the private master key is available
   *
   * @throws UnreadableWalletException
   */
    @Test
    public void trezorAccountChainUsingPrivateMasterKey() throws UnreadableWalletException {
        DeterministicSeed seed = new DeterministicSeed(TREZOR_SEED_PHRASE, null, "", secs);
        DeterministicKey privateMasterKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        log.debug("privateMasterKey = " + privateMasterKey);

        DeterministicKey key_m_44h = HDKeyDerivation.deriveChildKey(privateMasterKey, new ChildNumber(44 | ChildNumber.HARDENED_BIT));
        log.debug("key_m_44h deterministic key = " + key_m_44h);

        DeterministicKey key_m_44h_0h = HDKeyDerivation.deriveChildKey(key_m_44h, ChildNumber.ZERO_HARDENED);
        log.debug("key_m_44h_0h deterministic key = " + key_m_44h_0h);

        DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(key_m_44h_0h);

        DeterministicKey key_m_44h_0h_0h = deterministicHierarchy.deriveChild(key_m_44h_0h.getPath(), false, false, new ChildNumber(0, true));
        log.debug("key_m_44h_0h_0h = " + key_m_44h_0h_0h);

        ImmutableList<ChildNumber> key_m_44h_0h_0h_path = key_m_44h_0h_0h.getPath();
        log.debug("key_m_44h_0h_0h_path = " + key_m_44h_0h_0h_path);

        // Generate a chain using the derived key i.e. master private key is available
        DeterministicKeyChain accountChain = new DeterministicKeyChain(seed, key_m_44h_0h_0h_path);
        log.debug("accountChain = " + accountChain);

        assertNotNull(accountChain.getSeed());
        assertEquals(secs, accountChain.getSeed().getCreationTimeSeconds());

        checkAccountChain(accountChain);
    }

  /**
    * Test that a chain can be created for an account other than the HD account 0 of the BIP32 spec.
    * In this test a chain pointing to account 44 is created and some addresses tested.
    * This is a BIP44/ Trezor compatible chain. See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    *
    * In this test only the public master key is available
    *
    * @throws UnreadableWalletException
    */
    @Test
    public void accountChainUsingPublicMasterKey() throws UnreadableWalletException {

        DeterministicSeed seed = new DeterministicSeed(TREZOR_SEED_PHRASE, null, "", secs);

        DeterministicKey privateMasterKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        log.debug("privateMasterKey = " + privateMasterKey);

        DeterministicKey key_m_44h = HDKeyDerivation.deriveChildKey(privateMasterKey, new ChildNumber(44 | ChildNumber.HARDENED_BIT));

        DeterministicKey key_m_44h_0h = HDKeyDerivation.deriveChildKey(key_m_44h, ChildNumber.ZERO_HARDENED);

        DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(key_m_44h_0h);

        DeterministicKey key_m_44h_0h_0h = deterministicHierarchy.deriveChild(key_m_44h_0h.getPath(), false, false, new ChildNumber(0, true));

        ImmutableList<ChildNumber> key_m_44h_0h_0h_path = key_m_44h_0h_0h.getPath();

        DeterministicKey key_m_44h_0h_0h_pubOnly = key_m_44h_0h_0h.getPubOnly();

        // Generate a chain using the pubkey only of the root node
        DeterministicKeyChain accountChain = new DeterministicKeyChain(key_m_44h_0h_0h_pubOnly, key_m_44h_0h_0h_pubOnly.getCreationTimeSeconds(), key_m_44h_0h_0h_path);

        checkAccountChain(accountChain);
    }

    private void checkAccountChain(DeterministicKeyChain accountChain) {
       // Check the seed phrase given generates the expected BIP44 addresses
        DeterministicKey key0 = accountChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        log.debug("m/44'/0'/0'/0/0 key = " + key0);

        DeterministicKey key1 = accountChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        log.debug("m/44'/0'/0'/0/1 key = " + key1);

        DeterministicKey key2 = accountChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        log.debug("m/44'/0'/0'/0/2 key = " + key2);

        DeterministicKey key3 = accountChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        log.debug("m/44'/0'/0'/0/3 key = " + key3);

        DeterministicKey key4 = accountChain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        log.debug("m/44'/0'/0'/0/4 key = " + key4);

        assertEquals(EXPECTED_ADDRESS_0, key0.toAddress(mainnet).toString());
        assertEquals(EXPECTED_ADDRESS_1, key1.toAddress(mainnet).toString());
        assertEquals(EXPECTED_ADDRESS_2, key2.toAddress(mainnet).toString());
        assertEquals(EXPECTED_ADDRESS_3, key3.toAddress(mainnet).toString());
        assertEquals(EXPECTED_ADDRESS_4, key4.toAddress(mainnet).toString());
    }


    @Test(expected = IllegalStateException.class)
    public void watchingCannotEncrypt() throws Exception {
        final DeterministicKey accountKey = chain.getKeyByPath(DeterministicKeyChain.ACCOUNT_ZERO_PATH);
        chain = DeterministicKeyChain.watch(accountKey.getPubOnly());
        chain = chain.toEncrypted("this doesn't make any sense");
    }

    @Test
    public void bloom1() {
        DeterministicKey key2 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        DeterministicKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);

        int numEntries =
                (((chain.getLookaheadSize() + chain.getLookaheadThreshold()) * 2)   // * 2 because of internal/external
              + chain.numLeafKeysIssued()
              + 4  // one root key + one account key + two chain keys (internal/external)
                ) * 2;  // because the filter contains keys and key hashes.
        assertEquals(numEntries, chain.numBloomFilterEntries());
        BloomFilter filter = chain.getFilter(numEntries, 0.001, 1);
        assertTrue(filter.contains(key1.getPubKey()));
        assertTrue(filter.contains(key1.getPubKeyHash()));
        assertTrue(filter.contains(key2.getPubKey()));
        assertTrue(filter.contains(key2.getPubKeyHash()));

        // The lookahead zone is tested in bloom2 and via KeyChainGroupTest.bloom
    }

    @Test
    public void bloom2() throws Exception {
        // Verify that if when we watch a key, the filter contains at least 100 keys.
        DeterministicKey[] keys = new DeterministicKey[100];
        for (int i = 0; i < keys.length; i++)
            keys[i] = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        chain = DeterministicKeyChain.watch(chain.getWatchingKey());
        int e = chain.numBloomFilterEntries();
        BloomFilter filter = chain.getFilter(e, 0.001, 1);
        for (DeterministicKey key : keys)
            assertTrue("key " + key, filter.contains(key.getPubKeyHash()));
    }

    private String protoToString(List<Protos.Key> keys) {
        StringBuilder sb = new StringBuilder();
        for (Protos.Key key : keys) {
            sb.append(key.toString());
            sb.append("\n");
        }
        return sb.toString().trim();
    }

    private String checkSerialization(List<Protos.Key> keys, String filename) {
        try {
            String sb = protoToString(keys);
            String expected = Utils.getResourceAsString(getClass().getResource(filename));
            assertEquals(expected, sb);
            return expected;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
