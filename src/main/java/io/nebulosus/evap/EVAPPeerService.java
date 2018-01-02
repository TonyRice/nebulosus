package io.nebulosus.evap;

import com.hazelcast.core.ILock;
import com.hazelcast.core.IMap;
import io.ipfs.api.IPFS;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multiaddr.MultiAddress;
import io.ipfs.multihash.Multihash;
import io.jsync.Async;
import io.jsync.AsyncResult;
import io.jsync.Handler;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.Logger;
import io.jsync.app.core.service.ClusterService;
import io.jsync.buffer.Buffer;
import io.jsync.impl.ConcurrentHashSet;
import io.jsync.impl.DefaultFutureResult;
import io.jsync.json.JsonArray;
import io.jsync.json.JsonObject;
import io.jsync.json.impl.Base64;
import io.jsync.utils.CryptoUtils;
import io.jsync.utils.Token;
import io.nebulosus.ipfs.AsyncPubSub;
import io.nebulosus.ipfs.IPFSClientPool;
import io.nebulosus.util.CryptoUtil;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static io.jsync.utils.CryptoUtils.calculateSHA1;
import static io.nebulosus.util.CryptoUtil.*;

/**
 * The EVAPPeerService is a jsync.io ClusterService that provides a simple interface to the Evaporation Protocol. This makes
 * it very easy to stand up an EVAP peer.
 */
public class EVAPPeerService implements ClusterService {

    /**
     * This is a default list of bootstrap nodes that help facilitate communications within the evaporation network.
     * The IP addresses are hardcoded for now but may not be needed in the future. The Evaporation Network utilizes
     * these bootstrap nodes to help facilitate communications within the network.
     * <p>
     * (Yes I do run these nodes. Please do not attack them. - Tony Rice)
     */
    final public String[] DEFAULT_BOOTSTRAP_LIST = new String[]{
            "/ip4/51.254.18.68/tcp/4001/ipfs/QmdfahxLMqymEDEjXVYXTgtezJAtxL8L45pjfqncUu7786",
            "/ip4/51.254.18.69/tcp/4001/ipfs/QmPozFEzrwvy5BRM68rDbcZw6FPTYi9XA1cg1chiwPgA13"
    };

    private static EVAPPeerService localService = null;

    private static Set<Handler<EVAPPeerService>> startupHandlers = new LinkedHashSet<>();
    private static Runnable startupHandler = () -> {
        startupHandlers.forEach(handler -> {
            try {
                handler.handle(localService);
            } catch (Exception e) {
                localService.logger.error("Handler Error!", e);
            }
        });
        startupHandlers.clear();
    };

    /**
     * This is triggered when the EVAPPeerService is ready. If the service has already been started, the handler will
     * fire right away.
     *
     * @param handler the handler to run when the service is ready.
     */
    public static void ready(Handler<EVAPPeerService> handler) {
        if (localService != null && localService.started) {
            try {
                handler.handle(localService);
            } catch (Exception e) {
                localService.logger.error("Handler Error!", e);
            }
            return;
        }
        startupHandlers.add(handler);
    }

    /**
     * @return returns true if the local EVAPPeerService has been started
     */
    public static boolean ready() {
        return localService != null && localService.started;
    }

    /**
     * @return returns the current EVAPPeerService instance
     */
    public static EVAPPeerService getLocalService() {
        return localService;
    }

    private Logger logger = null;

    private Cluster cluster = null;
    private Async localAsync = null;

    private IPFSClientPool ipfsPool = null;
    private IPFS ipfs = null;

    private String peerKeyHash = null;

    private SecretKey secretKey = null;

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    private AsyncPubSub pubsub = null;

    private Set<String> trustedPeers = new ConcurrentHashSet<>();

    private Map<String, byte[]> cachedPublicKeyData = new ConcurrentHashMap<>();

    private IMap<String, Long> handledMessages = null;

    // This will store a list of peers. For example if you trust the Cirrostratus network you are trusting
    // paid peers routed through the network
    private Map<String, Date> localPeerTable = new ConcurrentHashMap<>();
    private Map<String, Handler<AsyncResult<Void>>> ackResponseHandlers = new ConcurrentHashMap<>();

    private Set<Handler<AsyncResult<EVAPMessage>>> messageHandlers = new ConcurrentHashSet<>();

    private boolean relayNode = false;
    private boolean multiLayerSupportEnabled = false;

    private boolean started = false;

    @Override
    public void start(Cluster owner) {

        if (started) {
            logger.error("It looks like the EVAPPeerService is already running!");
            return;
        }

        this.logger = owner.logger();
        this.cluster = owner;
        this.localAsync = owner.async();

        EVAPPeerService.localService = this;

        this.handledMessages = cluster.data().getMap("pevaphmsgs");

        // We really don't need a huge pool of IPFS clients. This is more
        // or less so we can ensure IPFS is started locally.
        ipfsPool = new IPFSClientPool(1);
        ipfs = ipfsPool.get();

        // Let's go ahead ensure the default bootstrap nodes are added
        try {
            for (String address : DEFAULT_BOOTSTRAP_LIST) {
                boolean shouldSkip = false;
                for (MultiAddress existingAddress : ipfs.bootstrap()) {
                    if (address.equals(existingAddress.toString())) {
                        shouldSkip = true;
                        break;
                    }
                }
                if (shouldSkip) {
                    continue;
                }
                logger.info("Attempting to add the default bootstrap \"" + address + "\".");
                ipfs.bootstrap.add(new MultiAddress(address));
            }
        } catch (IOException e) {
            logger.error("Failed to add default bootstrap nodes.", e);
        }

        // TODO enable open relay peers. These peers are generally not trusted and can easily be manipulated.
        // Only utilize this if you know what you are doing

        // Let's initialize this! We can't utilize EVAP
        // with out pubsub or IPFS.
        pubsub = new AsyncPubSub(ipfs);

        Config config = owner.config();

        JsonObject evapServiceConfig = config.rawConfig().getObject("evap", new JsonObject());

        boolean enabled = evapServiceConfig.getBoolean("enabled", true);

        // This means this node will relay messages!
        relayNode = evapServiceConfig.getBoolean("relay_node", false);

        String peerKeyPassword = evapServiceConfig.getString("key_password", "CHANGEME!!!!");

        boolean waitForPeers = evapServiceConfig.getBoolean("wait_for_peers", false);

        int minPeerCount = evapServiceConfig.getInteger("min_peer_count", 1);

        evapServiceConfig.putBoolean("relay_node", relayNode);

        evapServiceConfig.putBoolean("wait_for_peers", waitForPeers);
        evapServiceConfig.putNumber("min_peer_count", minPeerCount);

        evapServiceConfig.putBoolean("relay_node", relayNode);
        evapServiceConfig.putBoolean("enabled", enabled);

        Object[] _trustedPeers = evapServiceConfig.getArray("trusted_peers", new JsonArray()).toArray();

        for (Object trustedPeer : _trustedPeers) {
            logger.info("Adding trusted peer \"" + trustedPeer + "\".");
            trustedPeers.add(trustedPeer.toString());
        }

        try {

            logger.info("Initializing crypto support!");

            // BEGIN crypto initialization.

            String saltData = evapServiceConfig.getString("crypto_shash", "");

            if (saltData == null || saltData.isEmpty()) {
                logger.info("Generating new secret key...");
                secretKey = generateSecretKey(peerKeyPassword, salt -> {
                    try {
                        NamedStreamable.ByteArrayWrapper saltFile = new NamedStreamable.ByteArrayWrapper(CryptoUtils.calculateSHA1(salt), salt);
                        List<MerkleNode> addResult = ipfs.add(saltFile);

                        // Ensure we pin this.
                        ipfs.pin.add(addResult.get(0).hash);

                        evapServiceConfig.putString("crypto_shash", addResult.get(0).hash.toString());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            } else {
                logger.info("Restoring previous secret key...");
                Multihash saltPointer = Multihash.fromBase58(saltData);
                byte[] salt = ipfs.cat(saltPointer);
                secretKey = CryptoUtil.generateSecretKey(peerKeyPassword, salt);
            }

            // Let's go ahead and attempt to restore the Peer Key

            // Your Peer Key is basically your public key that identifies you.
            this.peerKeyHash = evapServiceConfig.getString("peer_key", null);
            String privateKeyData = evapServiceConfig.getString("private_key", null);

            if (peerKeyHash == null || privateKeyData == null) {

                logger.info("Generating new private public keypair...");

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

                kpg.initialize(DEFAULT_KEYPAIR_SIZE);

                KeyPair kp = kpg.generateKeyPair();

                this.privateKey = kp.getPrivate();
                this.publicKey = kp.getPublic();

                privateKeyData = Base64.encodeBytes(encryptData(new Buffer(privateKey.getEncoded())).getBytes());

                // Let's go ahead and save this public key as the peerkey
                NamedStreamable.ByteArrayWrapper saltFile = new NamedStreamable.ByteArrayWrapper("peerkey", Base64.encodeBytes(publicKey.getEncoded()).getBytes());
                List<MerkleNode> addResult = ipfs.add(saltFile);

                // Ensure we pin this.
                ipfs.pin.add(addResult.get(0).hash);
                peerKeyHash = addResult.get(0).hash.toString();

                logger.info("Finished generating new private public keypair...");


            } else {

                logger.info("Restoring private public keypair...");

                // Let's go ahead and do some verification on the peerKey data
                byte[] privateKeyBytes = decryptData(new Buffer(Base64.decode(evapServiceConfig.getString("private_key")))).getBytes();

                // Let's go ahead and retrieve the salt from IPFS
                byte[] publicKeyBytes = Base64.decode(new Buffer(ipfs.cat(Multihash.fromBase58(peerKeyHash))).toString());

                KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

                // Get an instance of Signature object and initialize it.
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);

                // Yeah this is pretty pointless.
                byte[] verifyData = "Hello World".getBytes();

                signature.update(verifyData);

                byte[] digitalSignature = signature.sign();

                PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

                signature.initVerify(publicKey);

                signature.update(verifyData);

                if (!signature.verify(digitalSignature)) {
                    logger.fatal("Signature verification failed! Your system may be compromised.");
                    return;
                }

                this.publicKey = publicKey;
                this.privateKey = privateKey;

                logger.info("Finished restoring private public keypair...");

            }

            logger.info("Crypto initialization finished...");

            // END crypto initialization

            // Note you can share your peer key hash or key in general.
            // Ideally you want to trust nodes utilizing a specific peer key.
            // The entire purpose of a peer key is to send data to it and
            // ensure it is encrypted.
            logger.info("Your peer key hash is \"" + peerKeyHash + "\". This can be shared directly with other peers that you trust or control.");

            // This will simply be a sha1 hash of the public key
            String peerAddr = calculateSHA1(publicKey.getEncoded());

            // Let's go ahead and subscribe to messages for this peer.
            // NOTE: One might consider this a security hole. You can easily find the peers
            // based on their public key.... that's the point though. The data is encrypted and nobody
            // has any idea what is being sent. It could be a relay message, or really anything. The NSA could easily
            // detect which peers are communicating with what. You also don't generally want to announce your public keys
            // to anybody. BUT!!!!!! EVAP supports chained public keys. A
            pubsub.sub(peerAddr, event -> {
                Buffer data;
                try {
                    data = new Buffer(Base64.decode(new String(event.getBinary("data", new byte[0]))));
                } catch (Exception ignored) {
                    data = new Buffer(new String(event.getBinary("data", new byte[0])));
                }

                // TODO ignore messages already received from previous servers.

                validateMessage(data, asyncResult -> {
                    try {

                        EVAPMessage message = asyncResult.result();

                        // This means this message was handled already by this cluster.
                        if (handledMessages.containsKey(message.getMessageToken())) {
                            logger.info("Ignoring already handled message \"" + message.getMessageToken() + "\".");
                            return;
                        }

                        ILock messageLock = cluster.hazelcast().getLock("evap.msg.lock." + message.getMessageToken());

                        if (messageLock.tryLock()) {
                            try {
                                Buffer decrypted = message.getData();

                                EVAPMessage.PayloadType payloadType = message.getPayloadType();

                                // Begin payload preprocessing.

                                if (message.getPayloadType() == EVAPMessage.PayloadType.ACK) {
                                    int hashLen = decrypted.getInt(0);
                                    String hash = decrypted.getString(4, hashLen + 4);
                                    if (ackResponseHandlers.containsKey(hash)) {
                                        localAsync.runOnContext(event1 -> ackResponseHandlers.remove(hash).handle(new DefaultFutureResult<Void>().setResult(null)));
                                    }
                                } else if (payloadType == EVAPMessage.PayloadType.PEER_RELAY_BROADCAST) {
                                    int peerHashLen = decrypted.getInt(0);
                                    String peerHash = decrypted.getString(4, peerHashLen + 4);

                                    if (trustedPeers.contains(peerHash)) {
                                        if (!localPeerTable.containsKey(peerHash)) {
                                            logger.info("Adding new relay peer to local peer table \"" + peerHash + "\".");
                                        }

                                        Calendar calendar = Calendar.getInstance();
                                        calendar.add(Calendar.MINUTE, 3);
                                        localPeerTable.put(peerHash, calendar.getTime());
                                    } else {
                                        String payloadPeerHash = message.getPayloadPeer();
                                        if (trustedPeers.contains(payloadPeerHash)) {
                                            if (!localPeerTable.containsKey(peerHash)) {
                                                logger.info("Adding new relay peer to local peer table \"" + peerHash + "\" from trusted peer \"" + payloadPeerHash + "\".");
                                            }
                                            Calendar calendar = Calendar.getInstance();
                                            calendar.add(Calendar.MINUTE, 3);
                                            localPeerTable.put(peerHash, calendar.getTime());
                                        }
                                    }
                                } else if (payloadType == EVAPMessage.PayloadType.PEER_LOG) {
                                    // This represents a log message from a trusted peer. If a peer is not trusted, all messages
                                    // will be discarded.

                                    String payloadPeerHash = message.getPayloadPeer();

                                    if (trustedPeers.contains(payloadPeerHash) || payloadPeerHash.equals(peerKeyHash)) {
                                        logger.info("EVAP Log (" + payloadPeerHash + "): " + decrypted);
                                    }
                                } else if (payloadType == EVAPMessage.PayloadType.MESSAGE_RELAY && relayNode) {
                                    String payloadPeerHash = message.getPayloadPeer();
                                    if (trustedPeers.contains(payloadPeerHash) || payloadPeerHash.equals(peerKeyHash)) {
                                        int relayPeerAddrLen = decrypted.getInt(0);
                                        String relayPeerAddr = decrypted.getString(4, 4 + relayPeerAddrLen);

                                        int messageDataLen = decrypted.getInt(4 + relayPeerAddrLen);
                                        Buffer messageData = decrypted.getBuffer(8 + relayPeerAddrLen, 8 + relayPeerAddrLen + messageDataLen);

                                        // This means there is no signature. So why the hell don't we sign it???
                                        // We trust the peer relaying it anyway and we are relaying the message.
                                        if(messageData.length() == messageData.getInt(0) + 4){
                                            Buffer encryptedData = messageData.getBuffer(4,
                                                    messageData.getInt(0) + 4);

                                            Buffer signature = CryptoUtil.signRSA(encryptedData, privateKey);

                                            Buffer newMessage = new Buffer();
                                            newMessage.appendInt(encryptedData.length());
                                            newMessage.appendBuffer(encryptedData);

                                            newMessage.appendInt(signature.length());
                                            newMessage.appendBuffer(signature);

                                            System.out.println(signature);

                                            broadcastMessage(relayPeerAddr, newMessage);
                                            return;
                                        }
                                        broadcastMessage(relayPeerAddr, messageData);
                                    }
                                }

                                // End payload preprocessing

                                messageHandlers.forEach(handler -> localAsync.runOnContext(event12 -> handler.handle(new DefaultFutureResult<>(message))));
                            } finally {
                                handledMessages.put(message.getMessageToken(), new Date().getTime());
                                messageLock.unlock();
                            }
                        }

                    } catch (Exception e) {
                        logger.error("Error Occurred!", e);
                    }
                });
            });

            localAsync.setPeriodic(2500, event -> {
                if(!started){
                    localAsync.cancelTimer(event);
                    return;
                }

                localPeerTable.forEach((peer, date) -> {
                    if((new Date()).after(date)){
                        localPeerTable.remove(peer);
                    }
                });
            });

            if (relayNode) {
                // We will only broadcast to trusted providers.

                // Begin relay broadcast message

                // This will go ahead and notify to your trusted
                // peers that you wish to act as a relay. This
                // means you can simply relay messages for those peers.

                Buffer relayMsg = new Buffer();

                relayMsg.appendInt(peerKeyHash.length());
                relayMsg.appendString(peerKeyHash);

                Runnable broadcastRelayNode = () -> {
                    try {
                        trustedPeers.forEach(peerKeyHash -> constructPeerMessage(EVAPPeerService.this.peerKeyHash, getPublicKey(peerKeyHash),
                                EVAPMessage.PayloadType.PEER_RELAY_BROADCAST.code, relayMsg, event -> broadcastMessage(event.result().getKey(), event.result().getValue())));

                        // TODO setup broadcast globally.

                    } catch (Exception e) {
                        logger.error("Relay Broadcast Error", e);
                    }
                };

                // Let's broadcast our node right away.
                broadcastRelayNode.run();

                // TODO make this configurable
                // Every 15 seconds we will broadcast ourself to each trusted peer.
                localAsync.setPeriodic(15000, event -> broadcastRelayNode.run());

                // End relay broadcast
            }

            evapServiceConfig.putString("peer_key", peerKeyHash);
            evapServiceConfig.putString("private_key", privateKeyData);

            config.rawConfig().putObject("evap", evapServiceConfig);
            config.save();

            // TODO Discover peers...

            // This might be very useful.

            if (waitForPeers) {
                // TODO do this.
                CountDownLatch waitLatch = new CountDownLatch(1);

                logger.info("Waiting for peers...");

                long waitTimer = localAsync.setPeriodic(750, event -> {
                    if (localPeerTable.size() > 0) {
                        logger.info("A peer has been found!");
                        waitLatch.countDown();
                    }
                });

                // We will wait at most 60 seconds.
                waitLatch.await(60, TimeUnit.SECONDS);

                localAsync.cancelTimer(waitTimer);
            }


        } catch (Exception e) {
            logger.error("EVAPPeerService error!", e);
        } finally {
            started = true;
            startupHandler.run();
        }
    }

    private void checkStarted() {
        if (!started) {
            throw new RuntimeException("It looks like the local EVAPPeerService has not been started!");
        }
    }

    /**
     * This allows you to publish a defai;t message destined for a specific peer.
     *
     * @param peerHash the peer you wish to receive the message
     * @param data     the data you wish to publish
     * @return returns an instance of this
     */
    public EVAPPeerService publish(String peerHash, Buffer data) {
        checkStarted();
        try {
            byte[] peerPublicKeyData = getPublicKey(peerHash);
            if (multiLayerSupportEnabled) {
                constructMultiLayerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.DEFAULT.code, data,
                        event -> broadcastMessage(event.result().getKey(), event.result().getValue()));
            } else {
                constructPeerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.DEFAULT.code, data,
                        event -> broadcastMessage(event.result().getKey(), event.result().getValue()));
            }
        } catch (Exception e) {
            logger.error("Error Occurred", e);
        }
        return this;
    }

    private void checkConfigurable(){
        if(started){
            throw new RuntimeException("It loos like the service has already been started!");
        }
    }

    public EVAPPeerService multiLayerSupportEnabled(boolean enabled){
        checkConfigurable();
        this.multiLayerSupportEnabled = enabled;
        return this;
    }

    public EVAPPeerService relayNode(boolean relayNode){
        checkConfigurable();
        this.relayNode = relayNode;
        return this;
    }

    /**
     * This allows you to publish a long message destined for a specific peer. This does not guarantee, the peer will receive
     * the message.
     *
     * @param peerHash the peer you wish to send the log to
     * @param message  the actual log message
     * @return returns an instance of this
     */
    public EVAPPeerService log(String peerHash, String message) {
        checkStarted();

        try {
            byte[] peerPublicKeyData = getPublicKey(peerHash);
            if (multiLayerSupportEnabled) {
                constructMultiLayerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PEER_LOG.code, new Buffer(message),
                        event -> broadcastMessage(event.result().getKey(), event.result().getValue()));
            } else {
                constructPeerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PEER_LOG.code, new Buffer(message),
                        event -> broadcastMessage(event.result().getKey(), event.result().getValue()));
            }
        } catch (Exception e) {
            logger.error("Error Occurred", e);
        }

        return this;
    }

    public EVAPPeerService pin(String peerKeyHash, Multihash multihash){
        return pin(peerKeyHash, -1, multihash, null);
    }

    public EVAPPeerService pin(String peerKeyHash, long expiresInMilliseconds, Multihash multihash){
        return pin(peerKeyHash, expiresInMilliseconds, multihash, null);
    }

    /**
     * This will attempt to publish a pin request for a specific MultiHash. This does not guarantee the specified
     * IPFS data will be persisted. This is generally utilized to facilitate p2p data transfer utilizing IPFS. By utilizing
     * the Evaporation Protocol, many peers can be easily utilized to persist your data.
     *
     * @param peerHash   the peer you wish to persist the data
     * @param multihash  the Multihash for the data you wish to persist
     * @param ackHandler a handler that is trigger when an acknowledgement is received
     */
    public EVAPPeerService pin(String peerHash, long expiresInMilliseconds, Multihash multihash, Handler<AsyncResult<Void>> ackHandler) {
        checkStarted();

        try {

            Buffer buffer = new Buffer();

            // Let's store thy hash.
            String hash = multihash.toString();

            buffer.appendInt(hash.length());
            buffer.appendString(hash);

            buffer.appendLong(expiresInMilliseconds);

            byte[] peerPublicKeyData = getPublicKey(peerHash);

            Runnable[] broadcastMessage = new Runnable[1];

            if (multiLayerSupportEnabled) {
                if (ackHandler != null) {
                    logger.warn("ACK responses are not currently supported by multilayer messages. This will be supported soon!");
                }
                constructMultiLayerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PIN_DATA.code, buffer, event -> {
                    broadcastMessage[0] = () -> broadcastMessage(event.result().getKey(), event.result().getValue());
                    broadcastMessage[0].run();
                });
            } else {
                constructPeerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PIN_DATA.code, buffer, event -> {
                    broadcastMessage[0] = () -> broadcastMessage(event.result().getKey(), event.result().getValue());
                    broadcastMessage[0].run();
                }, event -> {
                    if (event.failed()) {
                        broadcastMessage[0].run();
                    }
                    if (ackHandler != null) {
                        ackHandler.handle(event);
                    }
                }, 10, TimeUnit.SECONDS, 5);
            }

        } catch (Exception e) {
            logger.error("Error Occurred", e);
        }

        return this;
    }

    /**
     * This will add a peer to your trusted peer list.
     * @param peerHash the peer you wish to trust
     */
    public EVAPPeerService addTrustedPeer(String peerHash) {
        trustedPeers.add(peerHash);
        return this;
    }

    /**
     * This will remove a trusted peer from the trusted peer list.
     * @param peerHash the peer you no longer wish to trust.
     */
    public EVAPPeerService removeTrustedPeer(String peerHash) {
        trustedPeers.remove(peerHash);
        return this;
    }

    /**
     * This will go ahead and return a collection of your trusted peers.
     * @return a collection of trusted peers.
     */
    public Collection<String> trustedPeers() {
        return new LinkedHashSet<>(trustedPeers);
    }

    /**
     * This allows you to handle an EVAP message.
     * @param handler
     * @return
     */
    public EVAPPeerService handleMessage(Handler<AsyncResult<EVAPMessage>> handler) {
        messageHandlers.add(handler);
        return this;
    }

    private void validateMessage(Buffer bufferData, Handler<AsyncResult<EVAPMessage>> payloadHandler) {
        localAsync.executeBlocking(() -> {

            int dataLen = bufferData.getInt(0);

            Buffer data = bufferData.getBuffer(4, dataLen + 4);

            int hashLen = data.getInt(0);

            String msgHash = data.getString(4, hashLen + 4);

            int payloadLen = data.getInt(hashLen + 4);

            Buffer encryptedPayload = data.getBuffer(hashLen + 8, hashLen + payloadLen + 8);

            Buffer payload = CryptoUtil.decryptRSA(privateKey, encryptedPayload);

            int msgTokenLen = payload.getInt(8);

            int cryptoKeyLen = payload.getInt(12 + msgTokenLen);

            String cryptoKey = payload.getString(16 + msgTokenLen, 16 + msgTokenLen + cryptoKeyLen);

            int saltLen = payload.getInt(16 + msgTokenLen + cryptoKeyLen);

            byte[] salt = payload.getBytes(20 + msgTokenLen + cryptoKeyLen, 20 + msgTokenLen + cryptoKeyLen + saltLen);

            SecretKey secretKey = generateSecretKey(cryptoKey, salt);

            int cryptoLen = data.getInt(hashLen + payloadLen + 8);

            Buffer cryptoData = data.getBuffer(hashLen + payloadLen + 12, hashLen + payloadLen + cryptoLen + 12);

            Buffer decryptedData = decrypt(secretKey, cryptoData);

            int messageLen = decryptedData.getInt(0);
            Buffer messageData = decryptedData.getBuffer(4, 4 + messageLen);

            // Does this message require an acknowledgement???
            boolean requiresAck = decryptedData.length() > (4 + messageLen) && payload.getByte(payload.length() - 1) == (byte) 10;
            if (requiresAck) {
                // Yes ??? Okay let's verify the decrypted data is an ack message.
                if (decryptedData.getInt(4 + messageLen) == EVAPMessage.PayloadType.ACK.code) {
                    int ackPayloadLen = decryptedData.getInt(8 + messageLen);
                    Buffer ackPayload = decryptedData.getBuffer(12 + messageLen, 12 + messageLen + ackPayloadLen);

                    int ackReplyAddressLen = ackPayload.getInt(0);
                    String ackReplyAddress = ackPayload.getString(4, 4 + ackReplyAddressLen);

                    int ackReplyDataLen = ackPayload.getInt(4 + ackReplyAddressLen);
                    Buffer ackReplyData = ackPayload.getBuffer(8 + ackReplyAddressLen, 8 + ackReplyAddressLen + ackReplyDataLen);

                    // Let's send the actual acknowledgement message!
                    broadcastMessage(ackReplyAddress, ackReplyData);
                }
            }

            // Begin message verification.
            Buffer calculatedHashData = new Buffer();
            calculatedHashData.appendBytes(publicKey.getEncoded());
            calculatedHashData.appendBuffer(payload);
            calculatedHashData.appendBuffer(messageData);

            String calculatedMsgHash = CryptoUtils.calculateSHA512(calculatedHashData.getBytes());

            // TODO verify signed data -- Maybe not?? Is there signed data??

            // this helps us verify the contents of the message. not so much who is actually sending it.
            if (calculatedMsgHash.equals(msgHash)) {

                EVAPMessage message = new EVAPMessage(payload, messageData);

                // This is not required. This is only utilized generally when a message is received to it's
                // final destination.
                if(data.length() > hashLen + payloadLen + cryptoLen + 12){
                    int signatureLen = data.getInt(hashLen + payloadLen + cryptoLen + 12);
                    byte[] signatureData = data.getBytes(hashLen + payloadLen + cryptoLen + 16, hashLen + payloadLen + cryptoLen + signatureLen + 16);
                    String payloadPeer = message.getPayloadPeer();
                    byte[] peerBytes = getPublicKey(payloadPeer);
                    if(!CryptoUtil.verifyRSA(new Buffer(signatureData), cryptoData, generateRSAPublicKey(peerBytes))){
                        throw new RuntimeException("Peer message signature verification failed");
                    }
                }

                return message;
            }

            throw new RuntimeException("Message signature verification failed!");
        }, event -> {
            if(payloadHandler != null){
                payloadHandler.handle(event);
            }
        });
    }

    private Buffer decryptData(Buffer data) {
        return CryptoUtil.decrypt(secretKey, data);
    }

    private Buffer encryptData(Buffer data) {
        return CryptoUtil.encrypt(secretKey, data);
    }

    protected IPFS ipfs() {
        return ipfs;
    }

    protected AsyncPubSub pubsub() {
        return pubsub;
    }

    /**
     * This will return a raw byte array for the public key tied to a specific peer hash.
     *
     * @param peerHash the peer hash you wish to retrieve the public key for.
     * @return the raw byte array for the peers public key
     */
    private byte[] getPublicKey(String peerHash) {
        if (cachedPublicKeyData.containsKey(peerHash)) {
            return cachedPublicKeyData.get(peerHash);
        }

        IPFSClientPool ipfsClientPool = IPFSClientPool.defaultInstance();
        IPFS ipfs = ipfsClientPool.get();
        try {
            byte[] peerPubKey = ipfs.cat(Multihash.fromBase58(peerHash));
            String data = new String(peerPubKey);

            byte[] decoded = Base64.decode(data);

            cachedPublicKeyData.put(peerHash, decoded);

            return decoded;
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            ipfsClientPool.release(ipfs);
        }
    }

    /**
     * This is simply a helper function.
     */
    private void broadcastMessage(String address, Buffer message) {
        pubsub.pub(address, Base64.encodeBytes(message.getBytes()));
    }

    private void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, Handler<AsyncResult<Map.Entry<String, Buffer>>> resultHandler) {
        constructPeerMessage(payloadPeer, peerPublicKeyData, msgType, message, resultHandler, null, -1, null, -1);
    }

    private void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, Handler<AsyncResult<Map.Entry<String, Buffer>>> resultHandler, Handler<AsyncResult<Void>> ackHandler) {
        constructPeerMessage(payloadPeer, peerPublicKeyData, msgType, message, resultHandler, ackHandler, -1, null, 5);
    }

    private void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, Handler<AsyncResult<Map.Entry<String, Buffer>>> resultHandler, Handler<AsyncResult<Void>> ackHandler, long ackTimeout, TimeUnit ackTimeoutTimeUnit, int rebroadcastCount) {

        boolean requiresAck = ackHandler != null;

        PublicKey peerKey = generateRSAPublicKey(peerPublicKeyData);

        Buffer payloadMessage = new Buffer();

        payloadMessage.appendInt(EVAPMessage.PROTOCOL_VERSION);

        // Ensure the message type is added at the beginning of the payload
        payloadMessage.appendInt(msgType); // This essentially means that we want to pin some data on IPFS

        // This is pointless
        String msgToken = Token.generateToken().toHex();

        payloadMessage.appendInt(msgToken.length());
        payloadMessage.appendString(msgToken);

        String cryptoKey = generateRandomPassword();

        // We need to include this in the payload so the message can be decrypted.
        payloadMessage.appendInt(cryptoKey.length());
        payloadMessage.appendString(cryptoKey);

        // We need to generate a secret key to encrypt the data.
        SecretKey secretKey = generateSecretKey(cryptoKey, salt -> {
            payloadMessage.appendInt(salt.length);
            payloadMessage.appendBytes(salt);
        });

        // This consists of the actual recipient routing this message.
        payloadMessage.appendInt(payloadPeer.length());
        payloadMessage.appendString(payloadPeer);

        // TODO handle acknowledgement data here

        if (requiresAck) {
            payloadMessage.appendByte((byte) 10); // This means we must send an ack message back.
        }

        // Yes this is starting to look like some amazing callback hell... We are doing this to utilize jsync.io's event loop
        // to attempt to not utilize so much processing power.
        localAsync.executeBlocking(() -> {
            Buffer encryptedPayload = new Buffer();
            Buffer payloadData = CryptoUtil.encryptRSA(peerKey, payloadMessage);
            encryptedPayload.appendInt(payloadData.length());
            encryptedPayload.appendBuffer(payloadData);
            return encryptedPayload;
        }, event -> {
            Buffer encryptedPayload = event.result();
            localAsync.executeBlocking(() -> {
                Buffer hashData = new Buffer();
                hashData.appendBytes(peerPublicKeyData);
                hashData.appendBuffer(payloadMessage);
                hashData.appendBuffer(message);
                return CryptoUtils.calculateSHA512(hashData.getBytes());
            }, event15 -> {
                String msgHash = event15.result();

                Buffer broadcastMessage = new Buffer();
                broadcastMessage.appendInt(msgHash.length());
                broadcastMessage.appendString(msgHash);
                broadcastMessage.appendBuffer(encryptedPayload);

                localAsync.executeBlocking(() -> {
                    // This represents the actual message we want to send
                    Buffer messageToEncrypt = new Buffer();
                    messageToEncrypt.appendInt(message.length());
                    messageToEncrypt.appendBuffer(message);
                    // Let's construct the acknowledgement message
                    if (requiresAck) {

                        // Let's construct the ack payload that the final peer will broadcast.

                        // This is the message that we will receive back when the reply is received.
                        Buffer ackReplyMessage = new Buffer();
                        ackReplyMessage.appendInt(msgHash.length());
                        ackReplyMessage.appendString(msgHash);

                        // Let's create a handler that will go ahead and construct the message we are going
                        // to broadcast.
                        Handler<AsyncResult<Map.Entry<String, Buffer>>> ackMessageResultHandler = event152 -> localAsync.executeBlocking(() -> {

                            // Let's go ahead and construct our final message.

                            String peerAddress = event152.result().getKey();

                            Buffer encryptedAckMessage = event152.result().getValue();

                            // Let's construct the final ack message
                            Buffer finalAckMessage = new Buffer();

                            finalAckMessage.appendInt(peerAddress.length());
                            finalAckMessage.appendString(peerAddress);

                            finalAckMessage.appendInt(encryptedAckMessage.length());
                            finalAckMessage.appendBuffer(encryptedAckMessage);

                            // Let's ensure we add this so the peer knows the broadcast an ack message.
                            messageToEncrypt.appendInt(EVAPMessage.PayloadType.ACK.code);
                            messageToEncrypt.appendInt(finalAckMessage.length());
                            messageToEncrypt.appendBuffer(finalAckMessage);

                            // TODO - develop different and more efficient way of handling ack messages.

                            // Let's go ahead and check to see if an ack response was received.
                            // This honestly isn't the BEST thing in the world..
                            if (ackTimeout > 0 && ackTimeoutTimeUnit != null) {
                                long timeoutTimer = localAsync.setPeriodic(ackTimeoutTimeUnit.toMillis(ackTimeout), new Handler<Long>() {
                                    int retryCount = 0;

                                    @Override
                                    public void handle(Long event13) {
                                        retryCount++;
                                        if (retryCount > rebroadcastCount) {
                                            localAsync.cancelTimer(event13);
                                            ackResponseHandlers.remove(msgHash);
                                            localAsync.runOnContext(event1 -> ackHandler.handle(new DefaultFutureResult<>(new Exception("Acknowledgement not received before timeout! Maximum amount of message rebroadcasts reached."))));
                                            return;
                                        }
                                        localAsync.runOnContext(event1 -> ackHandler.handle(new DefaultFutureResult<>(new Exception("Acknowledgement not received before timeout! Rebroadcasting message..."))));
                                    }
                                });
                                ackResponseHandlers.put(msgHash, putEvent -> {
                                    localAsync.cancelTimer(timeoutTimer);
                                    localAsync.runOnContext(ignored -> ackHandler.handle(putEvent));
                                });
                            } else {
                                // There is no timeout.. so let's simply store the handler away.
                                ackResponseHandlers.put(msgHash, ackHandler);
                            }

                            // Encrypt the actual message data.
                            Buffer encryptedMessage = CryptoUtil.encrypt(secretKey, messageToEncrypt);

                            broadcastMessage.appendInt(encryptedMessage.length());
                            broadcastMessage.appendBuffer(encryptedMessage);

                            // If the payloadPeer is our own, we will go ahead and sign it.
                            if(payloadPeer.equals(EVAPPeerService.this.peerKeyHash)){
                                Buffer signedData = CryptoUtil.signRSA(encryptedMessage, privateKey);

                                broadcastMessage.appendInt(signedData.length());
                                broadcastMessage.appendBuffer(signedData);
                            }

                            Buffer finalBroadcastMessage = new Buffer();

                            finalBroadcastMessage.appendInt(broadcastMessage.length());
                            finalBroadcastMessage.appendBuffer(broadcastMessage);

                            return finalBroadcastMessage;
                        }, event14 -> localAsync.runOnContext(event12 -> resultHandler.handle(new DefaultFutureResult<>(new AbstractMap.SimpleEntry<>(calculateSHA1(peerPublicKeyData), event14.result())))));

                        // Let's go ahead and construct a message that will be sent back to us.

                        // Let's construct an ack message depending on our setup
                        if (multiLayerSupportEnabled && false) { // Disabled for now
                            // This will go ahead and ensure that the ack message that is sent, is always a multi-layered message.
                            constructMultiLayerMessage(payloadPeer, publicKey.getEncoded(),
                                    EVAPMessage.PayloadType.ACK.code, ackReplyMessage, ackMessageResultHandler);
                        } else {
                            // This is the message that we should receive back.
                            constructPeerMessage(payloadPeer, publicKey.getEncoded(),
                                    EVAPMessage.PayloadType.ACK.code, ackReplyMessage, ackMessageResultHandler);
                        }

                        // Let's return null since we do not want the handler
                        // to handle the response.
                        return null;
                    }

                    return messageToEncrypt;
                }, event151 -> {
                    if(event151.result() != null){
                        localAsync.executeBlocking(() -> {

                            Buffer encryptedData = CryptoUtil.encrypt(secretKey, event151.result());

                            broadcastMessage.appendInt(encryptedData.length());
                            broadcastMessage.appendBuffer(encryptedData);

                            // Let's ensure that this messages is verified.
                            if(payloadPeer.equals(EVAPPeerService.this.peerKeyHash)){
                                Buffer signedData = CryptoUtil.signRSA(encryptedData, privateKey);

                                broadcastMessage.appendInt(signedData.length());
                                broadcastMessage.appendBuffer(signedData);
                            }

                            Buffer finalBroadcastMessage = new Buffer();

                            finalBroadcastMessage.appendInt(broadcastMessage.length());
                            finalBroadcastMessage.appendBuffer(broadcastMessage);
                            return finalBroadcastMessage;
                        }, event1 -> localAsync.runOnContext(event12 -> resultHandler.handle(new DefaultFutureResult<>(new AbstractMap.SimpleEntry<>(calculateSHA1(peerPublicKeyData), event1.result())))));
                    }
                });
            });
        });
    }

    /**
     * This will construct an encrypted payload destined to route through multiple peers. It does this by passing it through
     * trusted peers, and their trusted peers. This provides anonymity when it comes to broadcasting messages to peers. The receiving peer
     * will never know the sending peer.
     *
     * @param finalPeerPublicKeyData
     * @param msgType
     * @param message
     * @param resultHandler
     */
    private void constructMultiLayerMessage(String payloadPeer, byte[] finalPeerPublicKeyData, int msgType, Buffer message, Handler<AsyncResult<Map.Entry<String, Buffer>>> resultHandler) {

        // TODO Note this is very broken.

        // TODO develop messages that are routed through many routes. This ensures a message lives.
        if (trustedPeers.size() == 0 || localPeerTable.size() == 0) {
            throw new RuntimeException("It looks like there aren't any relay peers available!");
        }
        // Note: this will construct a layered message meant to pass through multiple peers. These peers are
        // trusted relay peers and generally they must trust you to relay the messages.

        List<String> relayPeers = new LinkedList<>(localPeerTable.keySet());

        Collections.shuffle(relayPeers, CryptoUtil.getSecureRandom());

        relayPeers.forEach(new Consumer<String>() {

            boolean handlingAsync = false;

            List<Handler<Void>> nextHandlers = new CopyOnWriteArrayList<>();

            // We need to ensure we create the initial message.
            Buffer lastMessage = null;

            byte[] lastPeer = null;

            @Override
            public void accept(final String relayPeer) {
                Handler<Void> process = event -> {

                    final byte[] peerKeyData = getPublicKey(relayPeer);

                    handlingAsync = true;

                    String peerAddress = calculateSHA1(lastPeer);

                    Buffer relayMessage = new Buffer();

                    relayMessage.appendInt(peerAddress.length());
                    relayMessage.appendString(peerAddress);

                    relayMessage.appendInt(lastMessage.length());
                    relayMessage.appendBuffer(lastMessage);

                    constructPeerMessage(relayPeers.get(relayPeers.size() - 1).equals(relayPeer) ? payloadPeer : relayPeer, peerKeyData, EVAPMessage.PayloadType.MESSAGE_RELAY.code, relayMessage, new Handler<AsyncResult<Map.Entry<String, Buffer>>>() {
                        @Override
                        public void handle(AsyncResult<Map.Entry<String, Buffer>> event) {
                            Map.Entry<String, Buffer> result = event.result();
                            lastMessage = result.getValue();
                            lastPeer = peerKeyData;

                            handlingAsync = false;

                            if(nextHandlers.size() > 0){
                                localAsync.runOnContext(nextHandlers.remove(nextHandlers.size() - 1));
                            } else {
                                String lastPeerAddress = calculateSHA1(lastPeer);
                                localAsync.runOnContext(event1 -> resultHandler.handle(new DefaultFutureResult<>(new AbstractMap.SimpleEntry<>(lastPeerAddress, lastMessage))));
                            }
                        }
                    });
                };

                System.out.println("processing. " + relayPeer);

                if(handlingAsync){
                    nextHandlers.add(process);
                    return;
                }

                // We need to construct the initial message
                if (lastMessage.length() == 0 || lastMessage == null) {
                    constructPeerMessage(relayPeer, finalPeerPublicKeyData, msgType, message, event -> {
                        handlingAsync = true;
                        handlingAsync = true;
                        lastPeer = getPublicKey(event.result().getKey());
                        lastMessage = event.result().getValue();

                        localAsync.runOnContext(process);
                    });
                } else {
                    localAsync.runOnContext(process);
                }
            }
        });
    }

    @Override
    public void stop() {
        try {
            if (ipfs != null && ipfsPool != null) {
                pubsub.unsub(calculateSHA1(publicKey.getEncoded()));
                ipfsPool.release(ipfs);
            }
        } finally {
            started = false;
            localService = null;
        }
    }

    @Override
    public boolean running() {
        return started;
    }

    @Override
    public String name() {
        return "EVAPPeerService";
    }
}
