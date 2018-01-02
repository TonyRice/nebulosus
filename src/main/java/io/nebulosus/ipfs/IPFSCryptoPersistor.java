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
import io.jsync.json.JsonArray;
import io.jsync.json.JsonObject;
import io.jsync.json.impl.Base64;
import io.jsync.logging.Logger;
import io.jsync.logging.impl.LoggerFactory;
import io.jsync.utils.CryptoUtils;
import io.nebulosus.evap.EVAPMessage;
import io.nebulosus.evap.EVAPPeerService;
import io.nebulosus.util.CryptoUtil;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.util.*;
import java.util.concurrent.*;

import static io.nebulosus.util.CryptoUtil.DEFAULT_CIPHER;

/**
 * The IPFSCryptoPersistor is adds an IPFS based data persistence layer to jsync.io. It also implements the EVAPPeerService
 * to support the Evaporation Protocol. This helps ensure your IPFS data is persisted in a secure manner.
 **/
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

    private String shortMapHash = null;
    private String mapHash = null;

    private HTreeMap keyTableCache = null;
    private HTreeMap valueTableCache = null;

    private String keyTableIndex = null;
    private String valueTableIndex = null;

    private Date lastKeyUpdateTime = null;
    private int keyUpdateCount = 0;

    private Set<Handler<Void>> readyHandlers = new LinkedHashSet<>();

    private boolean initialized = false;

    private List<String> replicationPeers = new LinkedList<>();
    private List<String> evapPeers = new LinkedList<>();
    private boolean evapEnabled = false;

    @Override
    public void init(HazelcastInstance hazelcastInstance, Properties properties, String mapName) {

        if (initialized) {
            throw new RuntimeException("This has already been initialized!");
        }

        ClusterApp current = ClusterApp.activeInstance();

        cluster = current.cluster();
        hazelcast = hazelcastInstance;
        classLoader = current.getClass().getClassLoader();

        initialized = true;

        logger.info("Initializing the IPFSCryptoPersistor on the map \"" + mapName + "\".");

        ipfsClientPool = new IPFSClientPool(IPFSClientPool.DEFAULT_ADDRESS);

        // Read the config from the current cluster
        Config config = current.cluster().config();

        if (config == null) {
            config = new Config();
            config.open(config.getConfigPath());
        }

        JsonObject clusterConfig = config.rawConfig().getObject("cluster", new JsonObject());
        JsonObject ipfsConfig = clusterConfig.getObject("ipfs", new JsonObject());

        // This may be completely irrelevant
        //String store = ipfsConfig.getString("store", "ipfs_crypto");
        String storePass = ipfsConfig.getString("crypto_pass", "ChangeMeNow!");
        final String[] saltData = {ipfsConfig.getString("crypto_shash", "")};

        //ipfsConfig.putString("store", store);
        ipfsConfig.putString("crypto_pass", storePass);

        evapEnabled = ipfsConfig.getBoolean("evap_enabled", true);

        if(evapEnabled){
            logger.info("Initializing with EVAP support enabled.");
            for (Object evapPeer : ipfsConfig.getArray("evap_peers", new JsonArray())) {
                evapPeers.add(evapPeer.toString());
            }
        }

        // This allows us to handle some clustered
        // shared data.
        sharedData = hazelcast.getMap("shared" + mapHash);

        logger.info("Verifying connection to IPFS.");

        this.cryptoPass = storePass;

        logger.info("IPFS has been successfully connected!");

        IPFS ipfs = ipfsClientPool.get();

        try {
            if(saltData[0] == null || saltData[0].isEmpty()){
                secretKey = CryptoUtil.generateSecretKey(cryptoPass, salt -> {
                    try {
                        NamedStreamable.ByteArrayWrapper saltFile = new NamedStreamable.ByteArrayWrapper(CryptoUtils.calculateSHA1(salt), salt);
                        List<MerkleNode> addResult = ipfs.add(saltFile);

                        // Ensure we pin this.
                        ipfs.pin.add(addResult.get(0).hash);

                        saltData[0] = addResult.get(0).hash.toString();

                        ipfsConfig.putString("crypto_shash", addResult.get(0).hash.toString());

                    } catch (Exception e){
                        e.printStackTrace();
                    }
                });
            } else {
                // Let's go ahead and retrieve the salt from IPFS
                Multihash saltPointer = Multihash.fromBase58(saltData[0]);
                byte[] salt = ipfs.cat(saltPointer);
                secretKey = CryptoUtil.generateSecretKey(cryptoPass, salt);
            }

            mapHash = CryptoUtils.calculateHmacSHA1((mapName + saltData[0]).getBytes(), CryptoUtils.calculateSHA512((cryptoPass + mapName).getBytes()));
            shortMapHash = mapHash.substring(0, 12);

            Config finalConfig = config;

            EVAPPeerService.ready(evapPeerService -> {
                // TODO we do not want to handle key updates within our local cluster.
                // This is where we will handle messages from trusted EVAP peers.
                evapPeerService.handleMessage(event -> {
                    if(event.succeeded()){
                        EVAPMessage message = event.result();
                        Buffer messageData = message.getData();
                        // Always remember to keep it 100.
                        if(messageData.getInt(0) == 100){
                            int mapHashLen = messageData.getInt(4);
                            String mapHash = messageData.getString(8, mapHashLen + 8);
                            if(IPFSCryptoPersistor.this.mapHash.equals(mapHash)){
                                int dataLen = messageData.getInt(mapHashLen + 8);
                                Buffer data = messageData.getBuffer(mapHashLen + 12, mapHashLen + dataLen + 12);

                                eventBus.publish("nb.event." + mapHash, data);
                            }
                        }
                    }
                });
            });

            Handler<Void> finishStartup = ignored -> {

                localAsync = current.cluster().localAsync();
                eventBus = current.cluster().eventBus();

                // This is where we will receive KeyTable events

                eventBus.registerHandler("nb.event." + mapHash, (Handler<Message<Buffer>>) event -> {

                    decryptMessageData(event.body(), new Handler<AsyncResult<Buffer>>() {
                        @Override
                        public void handle(AsyncResult<Buffer> event) {

                            if(event.failed()){
                                if(event.cause() != null){
                                    event.cause().printStackTrace();
                                }
                                return;
                            }

                            Buffer evtBuffer = event.result();

                            int pos = 0;

                            int evtType = evtBuffer.getInt(pos);
                            pos += 4;

                            int nodeLen = evtBuffer.getInt(pos);
                            pos += 4;

                            String nodeId = evtBuffer.getString(pos, nodeLen + pos);
                            pos += nodeLen;

                            // Unless it is event type 75 which will simply
                            // save the latest key index to our configuration.
                            if (nodeId.equals(cluster.manager().nodeId()) && evtType != 75 && evtType != 70) {
                                return; // We do not need to do anything at all.
                            }

                            // This means we are receiving the latest
                            // data for a key.
                            if (evtType == 65) {

                                int keyLen = evtBuffer.getInt(pos);
                                pos += 4;

                                String key = evtBuffer.getString(pos, pos + keyLen);

                                pos += keyLen;

                                long blobLen = evtBuffer.getLong(pos);
                                pos += 8;

                                byte[] cryptoBlobData = evtBuffer.getBytes(pos, Math.toIntExact(pos + blobLen));

                                // Let's ensure we also store the data locally
                                storeLocally(key, cryptoBlobData);

                            } else if (evtType == 70) {

                                // Let's store this data. It is essentially the KeyTable index which is stored on IPFS.
                                // We initializing the database it will load all thy keys..
                                String vtIndex = Base64.encodeBytes(evtBuffer.getBytes(nodeLen + 8, evtBuffer.length())).replaceAll("\\n", "");

                                String previous = ipfsConfig.getString(shortMapHash + "vt_index", "");

                                if (!previous.isEmpty()) {
                                    logger.info("Replacing previous vt index \"" + previous + "\" with \"" + vtIndex + "\".");
                                }

                                ipfsConfig.putString(shortMapHash + "vt_index", vtIndex);

                                // Let's make sure we save the config
                                clusterConfig.putObject("ipfs", ipfsConfig);

                                finalConfig.rawConfig().putObject("cluster", clusterConfig);
                                finalConfig.save();

                                //logger.info("Saved latest value table index for the map \"" + mapName + "\".");

                                valueTableIndex = vtIndex;

                            } else if (evtType == 75) {

                                // Let's store this data. It is essentially the KeyTable index which is stored on IPFS.
                                // We initializing the database it will load all thy keys..
                                String ktIndex = Base64.encodeBytes(evtBuffer.getBytes(nodeLen + 8, evtBuffer.length())).replaceAll("\n", "");

                                String previous = ipfsConfig.getString(shortMapHash + "kt_index", "");

                                if (!previous.isEmpty()) {
                                    logger.info("Replacing previous key-table index \"" + previous + "\" with \"" + ktIndex + "\".");
                                }

                                ipfsConfig.putString(shortMapHash + "kt_index", ktIndex);

                                // Let's make sure we save the config
                                clusterConfig.putObject("ipfs", ipfsConfig);

                                finalConfig.rawConfig().putObject("cluster", clusterConfig);
                                finalConfig.save();

                                logger.info("Saved latest key table index for the map \"" + mapName + "\".");

                                keyTableIndex = ktIndex;

                            }
                        }
                    });
                });

                keyTableIndex = ipfsConfig.getString(shortMapHash + "kt_index", "");

                loadKeyTable();

                if(isMaster()){

                    // Since we are the master. We shall listen for new members
                    hazelcastInstance.getCluster().addMembershipListener(new MembershipListener() {
                        @Override
                        public void memberAdded(MembershipEvent membershipEvent) {
                            Buffer newIndexValues = new Buffer();
                            newIndexValues.appendInt(keyTableIndex.length());
                            newIndexValues.appendString(keyTableIndex);
                            newIndexValues.appendInt(valueTableIndex.length());
                            newIndexValues.appendString(valueTableIndex);

                            String memberId = membershipEvent.getMember().getUuid();

                            sharedData.put("indexs_" + memberId, newIndexValues.getBytes(), 10, TimeUnit.MINUTES);

                            logger.info("Published latest index values for the member \"" + memberId + "\".");
                        }

                        @Override
                        public void memberRemoved(MembershipEvent membershipEvent) {

                        }

                        @Override
                        public void memberAttributeChanged(MemberAttributeEvent memberAttributeEvent) {

                        }
                    });

                    // By default every 24 hours we will save a snapshot of the "Database"
                    localAsync.setPeriodic(TimeUnit.HOURS.toMillis(24), event -> {
                        saveValueTableCache(event13 -> saveKeyTableCache(false));
                    });

                    // Let's save the initial key table.
                    saveKeyTableCache(true, event -> {

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

                                        // et's make this number configurable in the future
                                        if(difference >= 60){
                                            logger.info("It has been " + difference + " seconds since the last key table update.");
                                            lastKeyUpdateTime = null;
                                            shouldUpdate = true;
                                        }
                                    }

                                    if(shouldUpdate){
                                        inUpdate = true;
                                        saveKeyTableCache(true, event12 -> {
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

                for (Handler<Void> readyHandler : readyHandlers) {
                    localAsync.runOnContext(readyHandler);
                }

                readyHandlers.clear();
            };

            if(!isMaster()){
                // every 3.5 seconds let's check if the cluster is safe..
                current.cluster().localAsync().setPeriodic(3500, event -> {
                    // This basically tells the cluster
                    if(!hazelcast.getPartitionService().isClusterSafe()){
                        logger.info("Cluster is not safe... not loading yet..");
                        return;
                    }
                    try {
                        cluster.async();
                    } catch (Exception ignored){
                        logger.info("Cluster is not safe... not loading yet..");
                        return;
                    }
                    current.cluster().localAsync().cancelTimer(event);
                    finishStartup.handle(null);
                });

            } else {
                finishStartup.handle(null);
            }

            // Let's make sure we save the config
            clusterConfig.putObject("ipfs", ipfsConfig);
            config.rawConfig().putObject("cluster", clusterConfig);
            config.save();

        } catch (Exception e) {
            if(config.isDebug()){
                e.printStackTrace();
            }
            throw new RuntimeException(e);
        } finally {
            ipfsClientPool.release(ipfs);
        }
    }

    /**
     * This is used to execute any handlers as soon as the cluster is ready.
     *
     * @param handler the handler you wish to execute
     */
    private void onReady(Handler<Void> handler){
        if(isReady()){
            handler.handle(null);
            return;
        }
        readyHandlers.add(handler);
    }

    /**
     * @return returns true if the cluster is ready
     */
    private boolean isReady(){
        return localAsync != null && keyTableCache != null && valueTableCache != null;
    }

    /**
     * @return returns true if we are the only or first node in the cluster.
     */
    private boolean isMaster() {
        try {
            Set<Member> members = hazelcast.getCluster().getMembers();
            // There's only one node.. so yeah.
            return members.size() == 1 || !members.isEmpty() && members.iterator().next() == hazelcast.getCluster().getLocalMember();
        } catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    /**
     * This will load all the data that is stored within NebulosusServer.
     */
    private void loadKeyTable() {

        long startTime = System.nanoTime();

        boolean forceUpdate = false;

        if(!isMaster()){
            String memberId = hazelcast.getCluster().getLocalMember().getUuid();

            Buffer indexData = new Buffer((byte[]) sharedData.get("indexs_" + memberId));

            int pos = 0;

            int ktIndexLen = indexData.getInt(pos);
            pos += 4;

            String ktIndex = indexData.getString(pos, pos + ktIndexLen);
            pos += ktIndexLen;

            int vtIndexLen = indexData.getInt(pos);
            pos += 4;

            String vtIndex = indexData.getString(pos, pos + vtIndexLen);

            if(!ktIndex.equals(keyTableIndex)){
                keyTableIndex = ktIndex;
            }

            if(!vtIndex.equals(valueTableIndex)){
                valueTableIndex = ktIndex;
            }

            forceUpdate = true;
        }

        String keyTableCacheFile = "nbdata/kt" + shortMapHash + ".db";
        String valueTableCacheFile = "nbdata/vt" + shortMapHash + ".db";

        if(!Files.exists(Paths.get("nbdata"))){
            try {
                Files.createDirectory(Paths.get("nbdata"));
            } catch (IOException ignored) {
            }
        }

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

                if(!Files.exists(Paths.get(keyTableCacheFile)) || forceUpdate){
                    // Looks like this file does not exist.
                    logger.info("\"" + keyTableCacheFile + "\" was not found. Restoring from \"" + keyTableIndex + "\".");

                    Buffer decryptedCryptoBlob = decryptCryptoBlob(Base64.decode(keyTableIndex));
                    try {
                        Files.write(Paths.get(keyTableCacheFile), decryptedCryptoBlob.getBytes());
                    } catch (IOException e) {
                        e.printStackTrace();
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

                if(!Files.exists(Paths.get(valueTableCacheFile)) || forceUpdate){
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

    public void saveKeyTableCache(){
        saveKeyTableCache(true, null);
    }

    public void saveKeyTableCache(boolean saveLocalCache){
        saveKeyTableCache(saveLocalCache, null);
    }

    public void saveKeyTableCache(Handler<AsyncResult<Void>> asyncResultHandler) {
        saveKeyTableCache(true, asyncResultHandler);
    }

    public void saveKeyTableCache(boolean saveLocalCache, Handler<AsyncResult<Void>> asyncResultHandler) {
        if(asyncResultHandler == null){
            asyncResultHandler = event -> { };
        }

        final Handler<AsyncResult<Void>> resultHandler = asyncResultHandler;

        if (isMaster()) {
            localAsync.runOnContext(ignoreThis -> {
                if (saveLocalCache) {
                    saveValueTableCache(event -> {
                        if (event.failed()) {
                            resultHandler.handle(event);
                            return;
                        }
                        _saveKeyTableCache(resultHandler);
                    });
                    return;
                }
                _saveKeyTableCache(resultHandler);
            });
            return;
        }
        resultHandler.handle(new DefaultFutureResult<>(new Exception("It looks like the key table could not be saved since you are not the master node.")));
    }

    private void _saveKeyTableCache(Handler<AsyncResult<Void>> asyncResultHandler) {

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

                String tmpFile = "nbdata/kt" + shortMapHash + ".tmp.db";

                if(!Files.exists(Paths.get("nbdata"))){
                    try {
                        Files.createDirectory(Paths.get("nbdata"));
                    } catch (IOException ignored) {
                    }
                }

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

                    HTreeMap tmpKeyTableCache = tmpFileDB.hashMap("ktcache").createOrOpen();

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

                    fs.readFile(tmpFile, new Handler<AsyncResult<Buffer>>() {
                        @Override
                        public void handle(AsyncResult<Buffer> event) {
                            createCryptoBlob(event.result(), new Handler<AsyncResult<Buffer>>() {
                                @Override
                                public void handle(AsyncResult<Buffer> event) {
                                    Buffer cryptoData = event.result();

                                    IPFSCryptoPersistor.this.keyTableIndex = Base64.encodeBytes(cryptoData.getBytes()).replaceAll("\n", "");

                                    publishEvent(75, cryptoData, true);

                                    // Don't ask why i'm doing this.
                                    localAsync.executeBlocking(() -> {
                                        fs.deleteSync(tmpFile);
                                        logger.info("Deleted temporary cache file at \"" + tmpFile + "\".");
                                        return null;
                                    }, (Handler<AsyncResult<Void>>) event12 -> {
                                        lock.forceUnlock();
                                        localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>()));
                                    });
                                }
                            }, true);
                        }
                    });
                });

                localAsync.executeBlocking(() -> {
                    if(fs.existsSync(tmpFile)){
                        fs.deleteSync(tmpFile);
                        logger.info("Deleted temporary cache file at \"" + tmpFile + "\".");
                    }
                    return null;
                }, (Handler<AsyncResult<Void>>) event -> syncMaster.handle(null));
            });
            return;
        }
        resultHandler.handle(new DefaultFutureResult<>(new Exception("It looks like the value table could not be saved since you are not the master node.")));
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

                String tmpFile = "nbdata/vt" + shortMapHash + ".tmp.db";

                if(!Files.exists(Paths.get("nbdata"))){
                    try {
                        Files.createDirectory(Paths.get("nbdata"));
                    } catch (IOException ignored) {
                    }
                }

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

                    fs.readFile(tmpFile, new Handler<AsyncResult<Buffer>>() {
                        @Override
                        public void handle(AsyncResult<Buffer> tmpFileRead) {
                            createCryptoBlob(tmpFileRead.result(), new Handler<AsyncResult<Buffer>>() {
                                @Override
                                public void handle(AsyncResult<Buffer> event) {

                                    Buffer cryptoData = event.result();

                                    IPFSCryptoPersistor.this.valueTableIndex = Base64.encodeBytes(cryptoData.getBytes()).replaceAll("\n", "");

                                    publishEvent(70, cryptoData, true);

                                    localAsync.executeBlocking(() -> {
                                        fs.deleteSync(tmpFile);
                                        logger.info("Deleting \"" + tmpFile + "\".");
                                        return null;
                                    }, (Handler<AsyncResult<Void>>) event12 -> {
                                        lock.forceUnlock();
                                        localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>()));
                                    });

                                }
                            }, true);
                        }
                    });
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

            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return new Buffer(cipher.doFinal(encrypted));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private void createCryptoBlob(Buffer data, Handler<AsyncResult<Buffer>> resultHandler) {
        createCryptoBlob(data, resultHandler, false);
    }

    /**
     * This is used to encrypt a piece of data and return a buffer with the data and iv stored with in it. This is generally
     * stored in memory and later stored via ipfs.
     */
    private void createCryptoBlob(Buffer data, Handler<AsyncResult<Buffer>> resultHandler, boolean storeOnIpfs) {
        localAsync.executeBlocking(() -> {
            try {
                Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                AlgorithmParameters params = cipher.getParameters();
                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
                byte[] dataToEnc = data.getBytes();
                return new AbstractMap.SimpleEntry<>(iv, cipher.doFinal(dataToEnc));
            } catch (Exception e){
                throw new RuntimeException(e);
            }
        }, new Handler<AsyncResult<Map.Entry<byte[], byte[]>>>() {
            @Override
            public void handle(AsyncResult<Map.Entry<byte[], byte[]>> event) {

                Map.Entry<byte[], byte[]> entry = event.result();

                byte[] iv = entry.getKey();
                byte[] encrypted = entry.getValue();

                Buffer newData = new Buffer();

                if (storeOnIpfs) {

                    // 12 is an identifier that let's us know that this
                    // is an encrypted ipfs blob.
                    newData.appendInt(12);

                    storeIPFSData(CryptoUtils.calculateSHA1(iv), encrypted, true, event12 -> {
                        String hash = event12.result();
                        newData.appendInt(hash.length());
                        newData.appendString(hash);

                        newData.appendInt(iv.length);
                        newData.appendBytes(iv);

                        localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>(newData)));

                    });
                    return;
                }


                // 13 signifies raw encrypted data.
                newData.appendInt(13);
                newData.appendInt(encrypted.length);
                newData.appendBytes(encrypted);

                newData.appendInt(iv.length);
                newData.appendBytes(iv);

                localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>(newData)));

            }
        });
    }

    private void decryptMessageData(Buffer data, Handler<AsyncResult<Buffer>> resultHandler) {
        localAsync.executeBlocking(() -> {

            try {
                int pos = 0;
                int ivLen = data.getInt(pos);
                pos += 4;

                byte[] iv = data.getBytes(pos, ivLen + pos);
                pos += ivLen;

                int dataLen = data.getInt(pos);
                pos += 4;

                byte[] encrypted = data.getBytes(pos, dataLen + pos);

                Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

                return new Buffer(cipher.doFinal(encrypted));

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, event -> resultHandler.handle(event));

    }

    private void encryptMessageData(Buffer data, Handler<AsyncResult<Buffer>> resultHandler) {
        localAsync.executeBlocking(() -> {
            try {
                Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                AlgorithmParameters params = cipher.getParameters();

                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

                // might be too slow
                byte[] encrypted = cipher.doFinal(data.getBytes());

                Buffer newData = new Buffer();

                newData.appendInt(iv.length);
                newData.appendBytes(iv);

                newData.appendInt(encrypted.length);
                newData.appendBytes(encrypted);

                return newData;

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, event -> resultHandler.handle(event));
    }

    private void publishEvent(int evtType, Buffer evtData, boolean publishEVAP) {

        Buffer evt = new Buffer();
        evt.appendInt(evtType);

        String nodeId = cluster.manager().nodeId();

        evt.appendInt(nodeId.length());
        evt.appendString(nodeId);

        evt.appendBuffer(evtData);

        encryptMessageData(evt, event -> {
            eventBus.publish("nb.event." + mapHash, event.result());

            if(evapEnabled && publishEVAP){

                // Let's broadcast this message to the peer
                EVAPPeerService.ready(evapPeerService -> {

                    Buffer dataBroadcast = new Buffer();
                    dataBroadcast.appendInt(100); // We must keep it 100 at all times.

                    dataBroadcast.appendInt(mapHash.length());
                    dataBroadcast.appendString(mapHash);

                    Buffer encryptedEvent = event.result();

                    dataBroadcast.appendInt(encryptedEvent.length());
                    dataBroadcast.appendBuffer(encryptedEvent);

                    // TODO we need to verify this..
                    for (String evapPeer : replicationPeers) {
                        evapPeerService.publish(evapPeer, dataBroadcast);
                    }
                });
            }

        });
    }

    private void storeIPFSData(String name, byte[] data, boolean save, Handler<AsyncResult<String>> resultHandler) {
        localAsync.executeBlocking(() -> {

            // Not sure if this is too safe :D
            NamedStreamable.ByteArrayWrapper encIpfsData = new NamedStreamable.ByteArrayWrapper(name, data);
            List<MerkleNode> addResult;
            IPFS ipfs = ipfsClientPool.get();
            try {
                addResult = ipfs.add(encIpfsData);
                if(save){
                    ipfs.pin.add(addResult.get(0).hash);
                }

                EVAPPeerService.ready(evapPeerService -> {
                    for (String evapPeer : evapPeers) {
                        evapPeerService.pin(evapPeer, addResult.get(0).hash);
                    }
                });
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                ipfsClientPool.release(ipfs);
            }

            return addResult.get(0).hash.toString();
        }, event -> resultHandler.handle(event));
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
        } else if(value instanceof byte[]){
            byte[] data = (byte[]) value;
            dataBuffer.appendInt(15);
            dataBuffer.appendLong(data.length);
            dataBuffer.appendBytes(data);
        } else if(value instanceof Buffer){
            Buffer data = (Buffer) value;
            dataBuffer.appendInt(16);
            dataBuffer.appendLong(data.length());
            dataBuffer.appendBuffer(data);
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

        onReady(new Handler<Void>() {
            @Override
            public void handle(Void event) {
                createCryptoBlob(dataBuffer, new Handler<AsyncResult<Buffer>>() {
                    @Override
                    public void handle(AsyncResult<Buffer> event) {
                        Buffer cryptoBlob = event.result();

                        String nKey = key.toString();

                        Buffer storeEvent = new Buffer();

                        storeEvent.appendInt(nKey.length());
                        storeEvent.appendString(nKey);

                        storeEvent.appendLong(cryptoBlob.length());

                        storeEvent.appendBuffer(cryptoBlob);

                        publishEvent(65, storeEvent, true);

                        storeLocally(nKey, cryptoBlob.getBytes());
                    }
                });
            }
        });

    }

    @Override
    public void storeAll(Map map) {
        map.forEach(this::store);
    }

    @Override
    public void delete(Object key) {
        onReady(ignored -> localAsync.runOnContext(event -> {
            String sKey = key.toString();
            String keyHash = CryptoUtils.calculateSHA1(sKey.getBytes());

            valueTableCache.remove(keyHash);
            keyTableCache.remove(sKey);

            keyUpdateCount++;
            lastKeyUpdateTime = new Date();
        }));
    }

    @Override
    public void deleteAll(Collection collection) {
        collection.forEach(o -> delete(o));
    }

    @Override
    public Object load(Object o) {
        if(isReady()){
            try {
                if (keyTableCache.containsKey(o)) {

                    // Let's retrieve the data automatically.
                    Buffer dataBuff = decryptCryptoBlob((byte[]) keyTableCache.get(o));

                    int pos = 0;
                    int dataType = dataBuff.getInt(pos);
                    pos += 4;
                    if (dataType == 1) {
                        int strLen = dataBuff.getInt(pos);
                        pos += 4;
                        return dataBuff.getString(pos, strLen + pos);
                    } else if (dataType == 2) {
                        return dataBuff.getLong(4);
                    } else if (dataType == 3) {
                        return dataBuff.getInt(4);
                    } else if (dataType == 4) {
                        return dataBuff.getFloat(4);
                    } else if(dataType == 15){
                        long dataLen = dataBuff.getLong(pos);
                        pos += 8;
                        return dataBuff.getBytes(pos, (int) (pos + dataLen));
                    } else if(dataType == 16){
                        long dataLen = dataBuff.getLong(pos);
                        pos += 8;
                        return dataBuff.getBuffer(pos, (int) (pos + dataLen));
                    } else if (dataType == 5) {

                        int classLen = dataBuff.getInt(pos);
                        pos += 4;
                        String className = dataBuff.getString(pos, classLen + pos);
                        pos += classLen;

                        int dataLen = dataBuff.getInt(pos);

                        pos += 4;
                        byte[] datas = dataBuff.getBytes(pos, dataLen + pos);

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
        return isReady() ? keyTableCache.keySet() : Collections.emptyList();
    }

    @Override
    public void destroy() {

    }
}
