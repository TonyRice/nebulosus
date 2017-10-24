package io.nebulosus.ipfs;

import com.hazelcast.core.*;
import io.ipfs.api.IPFS;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multihash.Multihash;
import io.jsync.Async;
import io.jsync.AsyncResult;
import io.jsync.Handler;
import io.jsync.app.ClusterApp;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.persistence.DataPersistor;
import io.jsync.app.core.persistence.DataType;
import io.jsync.app.core.persistence.IdentifiedDataType;
import io.jsync.buffer.Buffer;
import io.jsync.eventbus.EventBus;
import io.jsync.eventbus.Message;
import io.jsync.file.FileSystem;
import io.jsync.impl.DefaultFutureResult;
import io.jsync.json.JsonObject;
import io.jsync.json.impl.Base64;
import io.jsync.logging.Logger;
import io.jsync.logging.impl.LoggerFactory;
import io.jsync.utils.CryptoUtils;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.concurrent.*;

/**
 * The IPFSCryptoPersistor provides a powerful persistence layer to Hazelcast. This gives the system the ability
 * to persist data in a way that ensures it's longevity no matter what happens to a single node.
 */
public class IPFSCryptoPersistor implements DataPersistor {

    private Cluster cluster = null;
    private HazelcastInstance hazelcast = null;

    private Logger logger = LoggerFactory.getLogger(IPFSCryptoPersistor.class);
    private ClassLoader classLoader = null;

    private Async localAsync = null;
    private EventBus eventBus = null;

    private IMap<String, Object> sharedData = null;

    private IPFSClientPool ipfsClientPool = null;

    private DB keyDB = null;
    private DB fileDB = null;

    private SecretKey secretKey = null;
    private String cryptoPass = "";

    private String mapHash = null;

    private HTreeMap keyTableCache = null;
    private HTreeMap valueTableCache = null;

    private String keyTableIndex = null;
    private String valueTableIndex = null;

    private Date lastKeyUpdateTime = null;
    private int keyUpdateCount = 0;

    private boolean initialized = false;

    @Override
    public void init(HazelcastInstance hazelcastInstance, Properties properties, String mapName) {

        if (initialized) {
            throw new RuntimeException("This has already been initialized!");
        }

        initialized = true;

        logger.info("Initializing the IPFSCryptoPersistor on the map \"" + mapName + "\".");

        ClusterApp current = ClusterApp.activeInstance();

        cluster = current.cluster();
        hazelcast = cluster.hazelcast();
        classLoader = current.getClass().getClassLoader();

        // this map exists to provide shared data between each nodes. This is generally used
        // to store temporary data in memory.
        sharedData = current.cluster().data().getMap("p.n.s", false);

        localAsync = current.cluster().localAsync();
        eventBus = current.cluster().eventBus();

        ipfsClientPool = new IPFSClientPool(IPFSClientPool.DEFAULT_ADDRESS);

        // Read the config from the current cluster
        Config config = current.cluster().config();

        if (config == null) {
            config = new Config();
            config.open(config.getConfigPath());
        }

        JsonObject clusterConfig = config.rawConfig().getObject("cluster", new JsonObject());
        JsonObject ipfsConfig = clusterConfig.getObject("ipfs", new JsonObject());

        String store = ipfsConfig.getString("store", "ipfs_crypto");
        String storePass = ipfsConfig.getString("pass", "ChangeMeNow!");
        String saltData = ipfsConfig.getString("shash", "");

        ipfsConfig.putString("store", store);
        ipfsConfig.putString("pass", storePass);

        // This is how we are going to encrypt data.
        cryptoPass = CryptoUtils.calculateHmacSHA512(store + storePass, storePass + store);

        logger.info("Verifying connection to IPFS.");

        logger.info("IPFS has been successfully connected!");

        logger.info("Initializing MapDB for key table storage.");

        IPFS ipfs = ipfsClientPool.get();

        try {

            // TODO evaluate security of this.
            // Begin SecretKey generation
            SecretKey secret;

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            if (saltData.isEmpty()) {

                SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
                byte[] salt = new byte[16];
                sr.nextBytes(salt);

                NamedStreamable.ByteArrayWrapper saltFile = new NamedStreamable.ByteArrayWrapper(CryptoUtils.calculateSHA1(salt), salt);
                List<MerkleNode> addResult = ipfs.add(saltFile, true);
                saltData = addResult.get(0).hash.toString();

                KeySpec spec = new PBEKeySpec(cryptoPass.toCharArray(), salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(spec);
                secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            } else {
                Multihash saltPointer = Multihash.fromBase58(saltData);
                byte[] salt = ipfs.cat(saltPointer);
                KeySpec spec = new PBEKeySpec(cryptoPass.toCharArray(), salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(spec);
                secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            }

            secretKey = secret;

            // End SecretKey Generation

            ipfsConfig.putString("shash", saltData);

            // Let's make sure we save the config
            clusterConfig.putObject("ipfs", ipfsConfig);
            config.rawConfig().putObject("cluster", clusterConfig);
            config.save();

            mapHash = CryptoUtils.calculateSHA1(mapName.getBytes());

            Config finalConfig = config;
            // This is where we will receive KeyTable events

            eventBus.registerHandler("kt.event." + mapHash, (Handler<Message<Buffer>>) event -> {
                localAsync.executeBlocking(() -> {

                    // Let's get the actual message.
                    return decryptMessageData(event.body());

                }, event1 -> {
                    Buffer evtBuffer = event1.result();

                    int evtType = evtBuffer.getInt(0);

                    int nodeLen = evtBuffer.getInt(4);

                    String nodeId = evtBuffer.getString(8, nodeLen + 8);

                    // Unless it is event type 75 which will simply
                    // save the latest key index to our configuration.
                    if (nodeId.equals(cluster.manager().nodeId()) && evtType != 75 && evtType != 70) {
                        return; // We do not need to do anything at all.
                    }

                    // This means we are receiving the latest
                    // data for a key.
                    if (evtType == 65) {

                        // Key Update - 65
                        int keyLen = evtBuffer.getInt(nodeLen + 8);
                        String key = evtBuffer.getString(nodeLen + 12, nodeLen + keyLen + 12);

                        int blobLen = evtBuffer.getInt(nodeLen + keyLen + 12);

                        byte[] cryptoBlobData = evtBuffer.getBytes(nodeLen + keyLen + 12, nodeLen + blobLen + keyLen + 12);

                        storeLocally(key, cryptoBlobData);

                    } else if (evtType == 70) {

                        // Let's store this data. It is essentially the KeyTable index which is stored on IPFS.
                        // We initializing the database it will load all thy keys..
                        String vtIndex = Base64.encodeBytes(evtBuffer.getBytes(nodeLen + 8, evtBuffer.length())).replaceAll("\\n", "");

                        String previous = ipfsConfig.getString("vt_index", "");

                        if (!previous.isEmpty()) {
                            logger.info("Replacing previous vt index \"" + previous + "\" with \"" + vtIndex + "\".");
                        }

                        ipfsConfig.putString("vt_index", vtIndex);

                        // Let's make sure we save the config
                        clusterConfig.putObject("ipfs", ipfsConfig);

                        finalConfig.rawConfig().putObject("cluster", clusterConfig);
                        finalConfig.save();

                        logger.info("Saved latest vt index.");

                        this.valueTableIndex = vtIndex;

                    } else if (evtType == 75) {

                        // Let's store this data. It is essentially the KeyTable index which is stored on IPFS.
                        // We initializing the database it will load all thy keys..
                        String ktIndex = Base64.encodeBytes(evtBuffer.getBytes(nodeLen + 8, evtBuffer.length())).replaceAll("\n", "");

                        String previous = ipfsConfig.getString("kt_index", "");

                        if (!previous.isEmpty()) {
                            logger.info("Replacing previous key-table index \"" + previous + "\" with \"" + ktIndex + "\".");
                        }

                        ipfsConfig.putString("kt_index", ktIndex);

                        // Let's make sure we save the config
                        clusterConfig.putObject("ipfs", ipfsConfig);

                        finalConfig.rawConfig().putObject("cluster", clusterConfig);
                        finalConfig.save();

                        logger.info("Saved latest key table index.");

                        this.keyTableIndex = ktIndex;

                    }
                });
            });

            this.keyTableIndex = ipfsConfig.getString("kt_index", "");

            if(isMaster()){

                loadKeyTable();

                // By default every 24 hours we will save a snapshot of the "Database"
                localAsync.setPeriodic(TimeUnit.HOURS.toMillis(24), event -> {
                    saveValueTableCache(new Handler<AsyncResult<Void>>() {
                        @Override
                        public void handle(AsyncResult<Void> event) {
                            saveKeyTable(false);
                        }
                    });
                });

                // Let's save the initial key table.
                saveKeyTable(true, event -> {

                    // TODO improve detection of
                    // changes. This code below will not persist small updates
                    // immediately.
                    localAsync.setPeriodic(5000, new Handler<Long>() {

                        private int checkCount = 0;
                        private boolean inUpdate = false;

                        @Override
                        public void handle(Long event) {
                            if(isMaster() && !inUpdate){

                                boolean shouldUpdate = checkCount >= 50 && keyUpdateCount > 1 || keyUpdateCount > 100 * 1000;
                                if(lastKeyUpdateTime != null){

                                    Date curDate = new Date();
                                    int difference = (int) (curDate.getTime() - lastKeyUpdateTime.getTime())/1000;

                                    // TODO - Let's make this number configurable.
                                    if(difference >= 60){

                                        logger.info("It has been " + difference + " seconds since the last key table update.");

                                        lastKeyUpdateTime = null;
                                        shouldUpdate = true;
                                    }
                                }

                                if(shouldUpdate){
                                    inUpdate = true;
                                    saveKeyTable(true, event12 -> {
                                        inUpdate = false;
                                        checkCount = 0;
                                        keyUpdateCount = 0;
                                    });
                                }
                                checkCount++;
                            }
                        }
                    });
                });
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
        } finally {
            ipfsClientPool.release(ipfs);
        }

    }

    private boolean isMaster() {
        try {

            Set<Member> members = cluster.hazelcast().getCluster().getMembers();
            // There's only one node.. so yeah.
            return members.size() == 1 || !members.isEmpty() && members.iterator().next() == cluster.hazelcast().getCluster().getLocalMember();
        } catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    private void loadKeyTable() {
        long startTime = System.nanoTime();

        String keyTableCacheFile = "ktcache.db";
        String valueTableCacheFile = "vtcache.db";

        // This means we need to initialize a new one.
        if (keyTableIndex == null || keyTableIndex.isEmpty()) {
            logger.info("Initializing empty key table.");

            keyDB = DBMaker.fileDB(keyTableCacheFile)
                    .checksumHeaderBypass()
                    .fileMmapEnable()
                    .fileMmapEnableIfSupported()
                    .fileMmapPreclearDisable()
                    .cleanerHackEnable()
                    .make();

            keyTableCache = keyDB.hashMap("ktcache").createOrOpen();

            fileDB = DBMaker.fileDB(valueTableCacheFile)
                    .checksumHeaderBypass()
                    .fileMmapEnable()
                    .fileMmapEnableIfSupported()
                    .fileMmapPreclearDisable()
                    .cleanerHackEnable()
                    .make();

            valueTableCache = fileDB.hashMap("vtcache").createOrOpen();

        } else {

            try {

                // Let's attempt to load the key table from the data.

                logger.info("Searching for \"" + keyTableCacheFile + "\"...");

                if(!Files.exists(Paths.get(keyTableCacheFile))){
                    // Looks like this file does not exist.
                    logger.info("\"" + keyTableCacheFile + "\" was not found. Restoring from \"" + keyTableIndex + "\".");

                    Buffer decryptedCryptoBlob = decryptCryptoBlob(Base64.decode(keyTableIndex));
                    try {
                        Files.write(Paths.get(keyTableCacheFile), decryptedCryptoBlob.getBytes());
                    } catch (IOException e) {
                        throw new RuntimeException("Error restoring \"" + valueTableCacheFile + "\" from \"" + keyTableIndex + "\".", e);
                    }
                }

                keyDB = DBMaker.fileDB(keyTableCacheFile)
                        .checksumHeaderBypass()
                        .fileMmapEnable()
                        .fileMmapEnableIfSupported()
                        .fileMmapPreclearDisable()
                        .cleanerHackEnable()
                        .make();

                keyTableCache = keyDB.hashMap("ktcache").createOrOpen();

                String vtIndex = (String) keyTableCache.getOrDefault("____vt_index", valueTableIndex);

                keyTableCache.remove("____vt_index"); // We need to remove this - this is VERY important.

                logger.info("Searching for \"" + valueTableCacheFile + "\"...");

                if(!Files.exists(Paths.get(valueTableCacheFile))){
                    // Looks like this file does not exist.
                    logger.info("\"" + valueTableCacheFile + "\" was not found. Restoring from \"" + vtIndex + "\".");

                    Buffer decryptedCryptoBlob = decryptCryptoBlob(Base64.decode(vtIndex));
                    try {
                        Files.write(Paths.get(valueTableCacheFile), decryptedCryptoBlob.getBytes());
                    } catch (IOException e) {
                        throw new RuntimeException("Error restoring \"" + valueTableCacheFile + "\" from \"" + vtIndex + "\".", e);
                    }
                }

                fileDB = DBMaker.fileDB(valueTableCacheFile)
                        .checksumHeaderBypass()
                        .fileMmapEnable()
                        .fileMmapEnableIfSupported()
                        .fileMmapPreclearDisable()
                        .cleanerHackEnable()
                        .make();

                valueTableCache = fileDB.hashMap("vtcache").createOrOpen();

            } catch (Exception e){
                throw new RuntimeException("Failed to read the latest key table from \"" + keyTableIndex + "\".", e);
            }
        }

        long endTime = System.nanoTime();

        logger.info("Key table initialization finished with " + keyTableCache.size() + " keys loaded in " + ( TimeUnit.MILLISECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS) + "ms"));

    }

    public void saveKeyTable(){
        saveKeyTable(true, null);
    }

    public void saveKeyTable(boolean saveLocalCache){
        saveKeyTable(saveLocalCache, null);
    }

    public void saveKeyTable(Handler<AsyncResult<Void>> asyncResultHandler) {
        saveKeyTable(true, asyncResultHandler);
    }

    public void saveKeyTable(boolean saveLocalCache, Handler<AsyncResult<Void>> asyncResultHandler) {
        if(asyncResultHandler == null){
            asyncResultHandler = event -> { };
        }

        final Handler<AsyncResult<Void>> resultHandler = asyncResultHandler;

        if (isMaster()) {
            localAsync.runOnContext(ignoreThis -> {
                if (saveLocalCache) {
                    logger.info("Saving the local value cache first...");
                    saveValueTableCache(event -> {
                        if (event.failed()) {
                            resultHandler.handle(event);
                            return;
                        }
                        saveKeyTableCache(resultHandler);
                    });
                    return;
                }

                saveKeyTableCache(resultHandler);
            });
        }
    }

    private void saveKeyTableCache(Handler<AsyncResult<Void>> asyncResultHandler) {

        if(asyncResultHandler == null){
            asyncResultHandler = event -> {};
        }

        final Handler<AsyncResult<Void>> resultHandler = asyncResultHandler;

        if (isMaster()) {

            localAsync.runOnContext(ignoreThis -> {

                ILock lock = hazelcast.getLock("kt.update." + mapHash);

                if (lock.isLocked()) {
                    resultHandler.handle(new DefaultFutureResult<>(new RuntimeException("The local cache is currently being saved.")));
                    return;
                }

                lock.lock(5, TimeUnit.MINUTES);

                // Let's go ahead and update the master nb cache..
                // This is generally used to read any references
                // that were stored locally. The master can grow out of
                // sync. Therefor each node updates it's own copy eventually
                // synchronizing a master copy. The master copy is more
                // of a backup that is always persisted. When rebuilding the
                // kay table. We always ensure the master table is available.
                // When update, each non-master node will go ahead and re-open the
                // table with the latest values.

                String tmpFile = "ktcache.tmp.db";

                FileSystem fs = localAsync.fileSystem();

                logger.info("Attempting to save the local key table cache to \"" + tmpFile + "\".");

                Handler<Void> syncMaster = event -> localAsync.executeBlocking(() -> {

                    logger.info("Attempting to sync \"" + tmpFile + "\" cache file.");

                    DB tmpFileDB = DBMaker
                            .fileDB(tmpFile)
                            .checksumHeaderBypass()
                            .fileMmapEnable()
                            .fileMmapEnableIfSupported()
                            .fileMmapPreclearDisable()
                            .cleanerHackEnable()
                            .make();

                    HTreeMap tmpKeyTableCache = tmpFileDB.hashMap("ktcache").createOrOpen();;

                    tmpKeyTableCache.put("____vt_index", valueTableIndex);

                    try {
                        keyTableCache.forEach((o, o2) -> tmpKeyTableCache.put(o, o2));
                    } finally {
                        tmpKeyTableCache.close();
                        tmpFileDB.close();
                    }

                    logger.info("Synced all data to \"" + tmpFile + "\".");

                    return fs.existsSync(tmpFile);

                }, tmpFileResult -> {

                    if(tmpFileResult.failed()){
                        resultHandler.handle(new DefaultFutureResult<>(new IOException("Could not create \"" + tmpFile + "\"!")));
                        return;
                    }

                    logger.info("Attempting to encrypt the master file for temporary IPFS storage.");

                    fs.readFile(tmpFile, tmpFileRead -> localAsync.executeBlocking(() -> {

                        logger.info("Encrypting \"" + tmpFile + "\" for IPFS storage.");

                        // We are encrypting this data while storing
                        // the IV between each server. This will make it easy
                        // to decrypt.
                        return createCryptoBlob(tmpFileRead.result(), true);
                    }, cryptEvent -> {

                        if (cryptEvent.failed()) {
                            resultHandler.handle(new DefaultFutureResult<>(new IOException("Could not encrypt \"" + tmpFile + "\"!")));
                            return;
                        }

                        Buffer cryptoData = cryptEvent.result();

                        this.keyTableIndex = Base64.encodeBytes(cryptoData.getBytes()).replaceAll("\n", "");

                        publishEvent(75, cryptoData);

                        // Don't ask why i'm doing this.
                        localAsync.executeBlocking(() -> {
                            fs.deleteSync(tmpFile);
                            logger.info("Deleted temporary cache file at \"" + tmpFile + "\".");
                            return null;
                        }, (Handler<AsyncResult<Void>>) event12 -> {
                            lock.forceUnlock();
                            localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>()));
                        });
                    }));
                });

                localAsync.executeBlocking(() -> {
                    if(fs.existsSync(tmpFile)){
                        fs.deleteSync(tmpFile);
                        logger.info("Deleted temporary cache file at \"" + tmpFile + "\".");
                    }
                    return null;
                }, (Handler<AsyncResult<Void>>) event -> syncMaster.handle(null));
            });
        }
    }

    private void saveValueTableCache(Handler<AsyncResult<Void>> asyncResultHandler) {

        if(asyncResultHandler == null){
            // Create an empty handler for the hell of it.
            asyncResultHandler = event -> {};
        }

        final Handler<AsyncResult<Void>> resultHandler = asyncResultHandler;

        if (isMaster()) {

            localAsync.runOnContext(ignoreThis -> {

                ILock lock = hazelcast.getLock("vt.update." + mapHash);

                if (lock.isLocked()) {
                    resultHandler.handle(new DefaultFutureResult<>(new RuntimeException("The local cache is currently being saved.")));
                    return;
                }

                lock.lock(5, TimeUnit.MINUTES);

                // Let's go ahead and update the master nb cache..
                // This is generally used to read any references
                // that were stored locally. The master can grow out of
                // sync. Therefor each node updates it's own copy eventually
                // synchronizing a master copy. The master copy is more
                // of a backup that is always persisted. When rebuilding the
                // kay table. We always ensure the master table is available.
                // When update, each non-master node will go ahead and re-open the
                // table with the latest values.

                String tmpFile = "vtcache.tmp.db";

                FileSystem fs = localAsync.fileSystem();

                logger.info("Attempting to save the local value table cache to \"" + tmpFile + "\".");

                Handler<Void> syncMaster = event -> localAsync.executeBlocking(() -> {

                    logger.info("Attempting to sync \"" + tmpFile + "\" cache file.");

                    DB tmpFileDB = DBMaker
                            .fileDB(tmpFile)
                            .checksumHeaderBypass()
                            .fileMmapEnable()
                            .fileMmapEnableIfSupported()
                            .fileMmapPreclearDisable()
                            .cleanerHackEnable()
                            .make();

                    HTreeMap tmpValueCache = tmpFileDB.hashMap("vtcache").createOrOpen();

                    try {
                        valueTableCache.forEach((o, o2) -> tmpValueCache.put(o, o2));
                    } finally {
                        tmpValueCache.close();
                        tmpFileDB.close();
                    }

                    logger.info("Synced all data to \"" + tmpFile + "\".");

                    return fs.existsSync(tmpFile);
                }, tmpFileResult -> {

                    if(tmpFileResult.failed()){
                        resultHandler.handle(new DefaultFutureResult<>(new IOException("Could not create \"" + tmpFile + "\"!")));
                        return;
                    }

                    logger.info("Attempting to encrypt \"" + tmpFile + "\" for IPFS storage.");

                    fs.readFile(tmpFile, tmpFileRead -> localAsync.executeBlocking(() -> {

                        logger.info("Encrypting \"" + tmpFile + "\" for IPFS storage.");

                        // We are encrypting this data while storing
                        // the IV between each server. This will make it easy
                        // to decrypt.
                        return createCryptoBlob(tmpFileRead.result(), true);
                    }, cryptEvent -> {

                        if (cryptEvent.failed()) {
                            resultHandler.handle(new DefaultFutureResult<>(new IOException("Could not encrypt \"" + tmpFile + "\"!")));
                            return;
                        }

                        logger.info("Finished encrypting \"" + tmpFile + "\" for IPFS storage.");

                        Buffer cryptoData = cryptEvent.result();

                        this.valueTableIndex = Base64.encodeBytes(cryptoData.getBytes()).replaceAll("\n", "");

                        publishEvent(70, cryptoData);

                        localAsync.executeBlocking(() -> {
                            fs.deleteSync(tmpFile);
                            logger.info("Deleting \"" + tmpFile + "\".");
                            return null;
                        }, (Handler<AsyncResult<Void>>) event12 -> {
                            lock.forceUnlock();
                            localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>()));
                        });
                    }));
                });

                localAsync.executeBlocking(() -> {
                    if(fs.existsSync(tmpFile)){
                        fs.deleteSync(tmpFile);
                        logger.info("Deleting previous file at \"" + tmpFile + "\".");
                    }
                    return null;
                }, (Handler<AsyncResult<Void>>) event -> syncMaster.handle(null));
            });
        }
    }
    
    
    

    private Buffer decryptCryptoBlob(byte[] data){
        return decryptCryptoBlob(new Buffer(data));
    }

    private Buffer decryptCryptoBlob(Buffer cryptoBlob) {

        if (cryptoBlob == null) {
            throw new NullPointerException("The crypto blob shall not be null!");
        }

        int type = cryptoBlob.getInt(0);

        int pos = 4;
        int dataLen = cryptoBlob.getInt(pos);
        pos += 4;

        byte[] encrypted = new byte[0];

        if (type == 12) {
            String hash = cryptoBlob.getString(pos, dataLen + pos);
            pos += dataLen;

            IPFS ipfs = ipfsClientPool.get();
            try {

                Multihash multihash = Multihash.fromBase58(hash);
                encrypted = ipfs.cat(multihash);

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                ipfsClientPool.release(ipfs);
            }

        } else if (type == 13) {
            encrypted = cryptoBlob.getBytes(pos, dataLen + pos);

            pos += dataLen;

        } else if (type == 14) {

            // This is wo we can properly retrieve thy data.
            String localCacheHash = cryptoBlob.getString(pos, dataLen + pos);

            byte[] localBytes = (byte[]) valueTableCache.get(localCacheHash);

            if(localBytes != null){
                return decryptCryptoBlob(new Buffer(localBytes));
            }
        }


        int ivHashLen = cryptoBlob.getInt(pos);
        pos += 4;
        byte[] iv = cryptoBlob.getBytes(pos, ivHashLen + pos);

        try {

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return new Buffer(cipher.doFinal(encrypted));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private Buffer createCryptoBlob(Buffer data) {
        return createCryptoBlob(data, false);
    }

    /**
     * This is used to encrypt a piece of data and return a buffer with the data and iv stored with in it. This is generally
     * stored in memory and later stored via ipfs.
     *
     * @param data the data you wish to encrypt.
     * @return the "crypto blob"
     */
    private Buffer createCryptoBlob(Buffer data, boolean storeOnIpfs) {

        try {

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            AlgorithmParameters params = cipher.getParameters();

            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            byte[] dataToEnc = data.getBytes();

            byte[] encrypted = cipher.doFinal(dataToEnc);

            Buffer newData = new Buffer();

            if (storeOnIpfs) {

                // 12 is an identifier that let's us know that this
                // is an encrypted ipfs blob.
                newData.appendInt(12);

                String hash = storeIpfsData(CryptoUtils.calculateSHA1(iv), encrypted, true);

                newData.appendInt(hash.length());
                newData.appendString(hash);

                /*
                // This may be really resource intensive.
                String dataHash = CryptoUtils.calculateSHA1(dataToEnc);

                // This may never be useful.
                newData.appendInt(dataHash.length());
                newData.appendString(dataHash);*/

            } else {

                // 13 signifies raw encrypted data.
                newData.appendInt(13);
                newData.appendInt(encrypted.length);
                newData.appendBytes(encrypted);
            }

            newData.appendInt(iv.length);
            newData.appendBytes(iv);

            return newData;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Buffer decryptMessageData(Buffer data) {

        try {

            int ivHashLen = data.getInt(0);
            String ivHash = data.getString(4, ivHashLen + 4);

            int dataLen = data.getInt(ivHashLen + 4);

            // We need to retrieve the iv from Hazelcast.
            // We can also remove it too.
            byte[] iv = (byte[]) sharedData.remove(ivHash);

            byte[] encrypted = data.getBytes(ivHashLen + 8, dataLen + ivHashLen + 8);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return new Buffer(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException(e);

        }
    }

    private Buffer encryptMessageData(Buffer data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            AlgorithmParameters params = cipher.getParameters();

            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

            // might be too slow
            byte[] encrypted = cipher.doFinal(data.getBytes());

            Buffer newData = new Buffer();

            String ivHash = CryptoUtils.calculateSHA1(iv);

            // We need to store this here
            sharedData.put(ivHash, iv);

            newData.appendInt(ivHash.length());
            newData.appendString(ivHash);
            newData.appendInt(encrypted.length);
            newData.appendBytes(encrypted);

            return newData;

        } catch (BadPaddingException | IllegalBlockSizeException | InvalidParameterSpecException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private void publishEvent(int evtType, Buffer evtData) {

            localAsync.executeBlocking(() -> {

            Buffer evt = new Buffer();
            evt.appendInt(evtType);

            String nodeId = cluster.manager().nodeId();

            evt.appendInt(nodeId.length());
            evt.appendString(nodeId);

            evt.appendBuffer(evtData);

            return encryptMessageData(evt);
        }, event -> eventBus.publish("kt.event." + mapHash, event.result()));
    }

    private String storeIpfsData(String name, byte[] data, boolean save) {
        // Not sure if this is too safe :D
        NamedStreamable.ByteArrayWrapper encIpfsData = new NamedStreamable.ByteArrayWrapper(name, data);
        List<MerkleNode> addResult;
        // TODO autodetect pinning
        IPFS ipfs = ipfsClientPool.get();
        try {
            addResult = ipfs.add(encIpfsData, save);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } finally {
            ipfsClientPool.release(ipfs);
        }

        return addResult.get(0).hash.toString();
    }

    private void storeLocally(String key, byte[] data) {
        if (data.length > 1024) {
            localAsync.executeBlocking(() -> {

                String keyHash = CryptoUtils.calculateSHA1(key.getBytes());

                valueTableCache.put(keyHash, data);

                return keyHash;
            }, event15 -> localAsync.executeBlocking(() -> {
                // Since we are not the master node
                // it's definitely safe to save the shit here.
                String keyHash = event15.result();

                Buffer newData = new Buffer();
                newData.appendInt(14);
                newData.appendInt(keyHash.length());
                newData.appendString(keyHash);

                keyTableCache.put(key, newData.getBytes());

                return null;
            }, (Handler<AsyncResult<Void>>) event -> {
                keyUpdateCount++;
                lastKeyUpdateTime = new Date();
            }));
        } else {
            localAsync.executeBlocking(() -> {
                keyTableCache.put(key, data);
                return null;
            }, (Handler<AsyncResult<Void>>) event -> {
                keyUpdateCount++;
                lastKeyUpdateTime = new Date();
            });
        }
    }

    @Override
    public void store(Object key, Object value) {

        Buffer dataBuffer = new Buffer();

        if (value instanceof String) {
            String str = (String) value;
            dataBuffer.appendInt(1);
            dataBuffer.appendInt(str.length());
            dataBuffer.appendString(str);
        } else if (value instanceof Long) {
            Long numb = (Long) value;
            dataBuffer.appendInt(2);
            dataBuffer.appendLong(numb);
        } else if (value instanceof Integer) {
            Integer numb = (Integer) value;
            dataBuffer.appendInt(3);
            dataBuffer.appendInt(numb);
        } else if (value instanceof Float) {
            Float aFloat = (Float) value;
            dataBuffer.appendInt(4);
            dataBuffer.appendFloat(aFloat);
        } else if (value instanceof DataType) {

            String className = value.getClass().getCanonicalName();

            int classLength = className.length();

            dataBuffer.appendInt(5);
            dataBuffer.appendInt(classLength);
            dataBuffer.appendString(value.getClass().getCanonicalName());

            DataType dt = ((DataType) value);

            byte[] jsonData = dt.toJson().encode().getBytes();

            dataBuffer.appendInt(jsonData.length);
            dataBuffer.appendBytes(jsonData);

        } else if (value instanceof IdentifiedDataType) {
            String className = value.getClass().getCanonicalName();

            int classLength = className.length();

            dataBuffer.appendInt(6);
            dataBuffer.appendInt(classLength);
            dataBuffer.appendString(value.getClass().getCanonicalName());

            IdentifiedDataType dt = ((IdentifiedDataType) value);

            byte[] jsonData = dt.toJson().encode().getBytes();

            dataBuffer.appendInt(jsonData.length);
            dataBuffer.appendBytes(jsonData);

        } else {
            try {
                dataBuffer.appendInt(7);

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                ObjectOutput objectData = new ObjectOutputStream(buffer);
                objectData.writeObject(value);
                objectData.close();

                dataBuffer.appendInt(buffer.size());
                dataBuffer.appendBytes(buffer.toByteArray());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        localAsync.executeBlocking(() -> createCryptoBlob(dataBuffer), event -> {

            Buffer cryptoBlob = event.result();

            String nKey = key.toString();

            publishEvent(65, cryptoBlob);

            storeLocally(nKey, cryptoBlob.getBytes());
        });
    }

    @Override
    public void storeAll(Map map) {
        map.forEach(this::store);
    }

    @Override
    public void delete(Object key) {
        localAsync.runOnContext(event -> {
            String sKey = key.toString();
            String keyHash = CryptoUtils.calculateSHA1(sKey.getBytes());

            valueTableCache.remove(keyHash);
            keyTableCache.remove(sKey);

            keyUpdateCount++;
            lastKeyUpdateTime = new Date();
        });
    }

    @Override
    public void deleteAll(Collection collection) {
        collection.forEach(o -> delete(o));
    }

    @Override
    public Object load(Object o) {
        try {
            if (keyTableCache.containsKey(o)) {

                // Let's retrieve the data automatically.
                Buffer dataBuff = decryptCryptoBlob((byte[]) keyTableCache.get(o));

                int dataType = dataBuff.getInt(0);
                if (dataType == 1) {
                    return dataBuff.getString(8, dataBuff.getInt(4) + 8);
                } else if (dataType == 2) {
                    return dataBuff.getLong(4);
                } else if (dataType == 3) {
                    return dataBuff.getInt(4);
                } else if (dataType == 4) {
                    return dataBuff.getFloat(4);
                } else if (dataType == 5) {

                    int classLen = dataBuff.getInt(4);
                    String className = dataBuff.getString(8, classLen + 8);

                    int dataLen = dataBuff.getInt(classLen + 8);
                    byte[] datas = dataBuff.getBytes(classLen + 12, classLen + dataLen + 12);

                    JsonObject json = new JsonObject(new String(datas));

                    Class clazz = null; //cachedClasses.get(className);
                    if (clazz == null) {
                        clazz = classLoader.loadClass(className);
                        // We want to ensure that we store the new class inside the cache?
                        // The cache doesn't really expire because classes using this
                        // classloader should not dynamically change
                        //if (clazz != null) cachedClasses.put(className, clazz);
                    }
                    if (clazz != null) {
                        if (DataType.class.isAssignableFrom(clazz)) {
                            Method method = clazz.getMethod("loadJson", JsonObject.class);
                            Object newInstance = clazz.newInstance();
                            method.invoke(newInstance, json);
                            return newInstance;
                        } else if (IdentifiedDataType.class.isAssignableFrom(clazz)) {
                            Method method = clazz.getMethod("loadJson", JsonObject.class);
                            Object newInstance = clazz.newInstance();
                            method.invoke(newInstance, json);
                            return newInstance;
                        }
                    }

                } else if (dataType == 7) {
                    int dataLen = dataBuff.getInt(4);
                    InputStream buffer = new ByteArrayInputStream(dataBuff.getBytes(8, dataLen + 8));
                    ObjectInput input = new ObjectInputStream(buffer) {
                        @Override
                        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException,
                                ClassNotFoundException {
                            return classLoader.loadClass(desc.getName());
                        }
                    };
                    return input.readObject();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public Map loadAll(Collection collection) {
        Map map = new HashMap();
        collection.forEach(o -> map.put(o, load(o)));
        return map;
    }

    @Override
    public Iterable loadAllKeys() {
        return keyTableCache.keySet();
    }

    @Override
    public void destroy() {

    }
}
