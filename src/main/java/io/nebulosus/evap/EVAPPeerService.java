package io.nebulosus.evap;

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
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import static io.jsync.utils.CryptoUtils.calculateSHA1;
import static io.nebulosus.util.CryptoUtil.*;

/**
 * The EVAPPeerService makes it as simple as possible to implement the Evaporation Protocol within a
 * jsync.io based application.
 */
public class EVAPPeerService implements ClusterService {

    /**
     * This is a default list of bootstrap nodes that help facilitate communications within the evaporation network.
     * The IP addresses are hardcoded for now but may not be needed in the future. The Evaporation Network utilizes
     * these bootstrap nodes to help facilitate communications within the network.
     *
     * (Yes I do run these nodes. Please do not attack them. - Tony Rice)
     */
    final public String[] DEFAULT_BOOTSTRAP_LIST = new String[]{
            "/ip4/51.254.18.68/tcp/4001/ipfs/QmdfahxLMqymEDEjXVYXTgtezJAtxL8L45pjfqncUu7786",
            "/ip4/51.254.18.69/tcp/4001/ipfs/QmPozFEzrwvy5BRM68rDbcZw6FPTYi9XA1cg1chiwPgA13",
            "/ip4/51.254.18.70/tcp/4001/ipfs/QmbEKxRycKnu6sNpTcKirCuF8McasLwoZSboLVbm1b31RN",
            "/ip4/51.254.18.71/tcp/4001/ipfs/QmSi3BPyVwZ6PKBQSZrtjFaH435f6Dmrmnw1g328icZ9fn"
    };

    private static EVAPPeerService localService = null;

    private static Set<Handler<EVAPPeerService>> startupHandlers = new LinkedHashSet<>();
    private static Runnable startupHandler = () -> {
        startupHandlers.forEach(handler -> {
            try {
                handler.handle(localService);
            } catch (Exception e){
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
                handler.handle(null);
            } catch (Exception e){
                localService.logger.error("Handler Error!", e);
            }
            return;
        }
        startupHandlers.add(handler);
    }

    /**
     * @return returns true if the local EVAPPeerService has been started
     */
    public static boolean ready(){
        return localService != null && localService.started;
    }

    /**
     * @return returns the current EVAPPeerService instance
     */
    public static EVAPPeerService getLocalService(){
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

    // This will store a list of peers. For example if you trust the Cirrostratus network you are trusting
    // paid peers routed through the network
    private Map<String, Date> localPeerTable = new ConcurrentHashMap<>();
    private Map<String, Handler<AsyncResult<Void>>> ackResponseHandlers = new ConcurrentHashMap<>();

    private Handler<EVAPMessage> messageHandler = null;

    private boolean multiLayerSupportEnabled = true;

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

        // Let's initialize this! We can't utilize EVAP
        // with out pubsub or IPFS.
        pubsub = new AsyncPubSub(ipfs);

        Config config = owner.config();

        JsonObject evapServiceConfig = config.rawConfig().getObject("evap", new JsonObject());

        boolean enabled = evapServiceConfig.getBoolean("enabled", true);

        // This means this node will relay messages!
        boolean relayNode = evapServiceConfig.getBoolean("relay_node", false);

        String peerKeyPassword = evapServiceConfig.getString("key_password", "CHANGEME!!!!");

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

            pubsub.sub(peerAddr, event -> {
                Buffer data;
                try {
                    data = new Buffer(Base64.decode(new String(event.getBinary("data", new byte[0]))));
                } catch (Exception ignored) {
                    data = new Buffer(new String(event.getBinary("data", new byte[0])));
                }

                validateMessage(data, message -> {
                    try {

                        Buffer payload = message.getPayload();

                        Buffer decrypted = message.getData();

                        EVAPMessage.PayloadType payloadType = message.getPayloadType();

                        // Begin payload preprocessing.

                        if(message.getPayloadType() == EVAPMessage.PayloadType.ACK){
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

                                localPeerTable.put(peerHash, new Date());
                            } else {
                                String payloadPeerHash = message.getPayloadPeer();
                                if (trustedPeers.contains(payloadPeerHash)) {
                                    if (!localPeerTable.containsKey(peerHash)) {
                                        logger.info("Adding new relay peer to local peer table \"" + peerHash + "\" from trusted peer \"" + payloadPeerHash + "\".");
                                    }
                                    localPeerTable.put(peerHash, new Date());
                                }
                            }
                        } else if (payloadType == EVAPMessage.PayloadType.PEER_LOG) {
                            // This represents a log message from a trusted peer. If a peer is not trusted, all messages
                            // will be discarded.

                            String payloadPeerHash = message.getPayloadPeer();

                            if (trustedPeers.contains(payloadPeerHash) || payloadPeerHash.equals(peerKeyHash)) {
                                logger.info("EVAP Log (" + payloadPeerHash + "): " + decrypted);
                            }
                        } else if(payloadType == EVAPMessage.PayloadType.MESSAGE_RELAY && relayNode){
                            String payloadPeerHash = message.getPayloadPeer();
                            if(trustedPeers.contains(payloadPeerHash) || payloadPeerHash.equals(peerKeyHash)){
                                int relayPeerAddrLen = decrypted.getInt(0);
                                String relayPeerAddr = decrypted.getString(4, 4 + relayPeerAddrLen);

                                int relayDataLen = decrypted.getInt(4 + relayPeerAddrLen);
                                Buffer relayData = decrypted.getBuffer(8 + relayPeerAddrLen, 8 + relayPeerAddrLen + relayDataLen);
                                broadcastMessage(relayPeerAddr, relayData);
                            }
                        }

                        // End payload preprocessing

                        if(messageHandler != null){
                            messageHandler.handle(new EVAPMessage(payload, decrypted));
                        }
                    } catch (Exception e) {
                        logger.error("Error Occurred!", e);
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
                        trustedPeers.forEach(peerKeyHash -> constructPeerMessage(EVAPPeerService.this.peerKeyHash, getPublicKey(peerKeyHash), EVAPMessage.PayloadType.PEER_RELAY_BROADCAST.code, relayMsg, EVAPPeerService.this::broadcastMessage));
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

        } catch (Exception e) {
            logger.error("EVAPPeerService error!", e);
        } finally {
            started = true;
            startupHandler.run();
        }
    }

    public EVAPPeerService messageHandler(Handler<EVAPMessage> handler){
        this.messageHandler = handler;
        return this;
    }

    private void validateMessage(Buffer data, Handler<EVAPMessage> payloadHandler) {
        validateMessage(false, data, payloadHandler);
    }

    private void validateMessage(boolean requireTrusted, Buffer bufferData, Handler<EVAPMessage> payloadHandler) {

        int dataLen = bufferData.getInt(0);

        Buffer data = bufferData.getBuffer(4, dataLen + 4);

        int hashLen = data.getInt(0);

        String msgHash = data.getString(4, hashLen + 4);

        int payloadLen = data.getInt(hashLen + 4);

        Buffer encryptedPayload = data.getBuffer(hashLen + 8, hashLen + payloadLen + 8);

        Buffer payload = CryptoUtil.decryptRSA(privateKey, encryptedPayload);

        int msgTokenLen = payload.getInt(8);

        // This helps identify a message - Technically a message can be sent out
        // through many different routes. This provides a reference so we can know we
        // already received the message - TODO
        String msgToken = payload.getString(12, 12 + msgTokenLen);

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

                // Let's send the actual message!
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
            if (payloadHandler != null) {
                payloadHandler.handle(new EVAPMessage(payload, messageData));
            }
            return;
        }

        throw new RuntimeException("Invalid message!");
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

    protected void addTrustedRelayPeer(String peerHash) {
        trustedPeers.add(peerHash);
    }

    protected void removeTrustedRelayPeer(String peerHash) {
        trustedPeers.remove(peerHash);
    }

    protected boolean isTrustedRelayPeer(String peerHash) {
        return trustedPeers.contains(peerHash);
    }

    protected Set<String> listTrustedRelayPeers() {
        return new LinkedHashSet<>(trustedPeers);
    }

    private void checkStarted() {
        if (!started) {
            throw new RuntimeException("It looks like the local EVAPPeerService has not been started!");
        }
    }

    /**
     * This will return a raw byte array for the public key tied to a specific peer hash.
     *
     * @param peerHash the peer hash you wish to retrieve the public key for.
     * @return the raw byte array for the peers public key
     */
    private byte[] getPublicKey(String peerHash) {
        IPFSClientPool ipfsClientPool = IPFSClientPool.defaultInstance();
        IPFS ipfs = ipfsClientPool.get();
        try {
            byte[] peerPubKey = ipfs.cat(Multihash.fromBase58(peerHash));
            String data = new String(peerPubKey);
            return Base64.decode(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            ipfsClientPool.release(ipfs);
        }
    }

    /**
     * This allows you to broadcast a log message to a specified peer. Generally
     * a peer will only display a message from a trusted peer.
     *
     * @param peerHash the peer you wish to send the log to
     * @param message  the actual log message
     */
    public EVAPPeerService peerLog(String peerHash, String message) {
        checkStarted();

        try {
            byte[] peerPublicKeyData = getPublicKey(peerHash);
            constructPeerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PEER_LOG.code, new Buffer(message), this::broadcastMessage);
        } catch (Exception e) {
            logger.error("Error Occurred", e);
        }

        return this;
    }

    /**
     * This will attempt to request that a specific peer ensures the persistence of a specific piece of data.
     *
     * @param peerHash   the peer you wish to persist the data
     * @param multihash  the Multihash for the data you wish to persist
     * @param ackHandler a handler that is trigger when an acknowledgement is received
     */
    public EVAPPeerService persistData(String peerHash, Multihash multihash, Handler<AsyncResult<Void>> ackHandler) {
        checkStarted();

        try {

            Buffer buffer = new Buffer();

            // Let's store thy hash.
            String hash = multihash.toString();

            logger.info("Attempting to persist the data located at \"" + hash + "\'.");

            buffer.appendInt(hash.length());
            buffer.appendString(hash);

            byte[] peerPublicKeyData = getPublicKey(peerHash);

            Runnable[] broadcastMessage = new Runnable[1];

            if(multiLayerSupportEnabled){
                if(ackHandler != null){
                    logger.warn("ACK responses are not currently supported by multilayer messages. This will be supported soon!");
                }
                constructMultiLayerMessage(peerPublicKeyData, EVAPMessage.PayloadType.PIN_DATA.code, buffer, new BiConsumer<String, Buffer>() {
                    @Override
                    public void accept(String peerAddress, Buffer peerMessage) {
                        broadcastMessage[0] = () -> broadcastMessage(peerAddress, peerMessage);
                        broadcastMessage[0].run();
                    }
                });
            } else {
                constructPeerMessage(peerKeyHash, peerPublicKeyData, EVAPMessage.PayloadType.PIN_DATA.code, buffer, (peerAddress, peerMessage) -> {
                    broadcastMessage[0] = () -> broadcastMessage(peerAddress, peerMessage);
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
     * This is simply a helper function.
     */
    private void broadcastMessage(String address, Buffer message) {
        pubsub.pub(address, Base64.encodeBytes(message.getBytes()));
    }

    protected void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, BiConsumer<String, Buffer> consumer){
        constructPeerMessage(payloadPeer, peerPublicKeyData, msgType, message, consumer, null, -1, null, -1);
    }

    protected void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, BiConsumer<String, Buffer> consumer, Handler<AsyncResult<Void>> ackHandler){
        constructPeerMessage(payloadPeer, peerPublicKeyData, msgType, message, consumer, ackHandler, -1, null, 5);
    }

    protected void constructPeerMessage(String payloadPeer, byte[] peerPublicKeyData, int msgType, Buffer message, BiConsumer<String, Buffer> consumer, Handler<AsyncResult<Void>> ackHandler, long ackTimeout, TimeUnit ackTimeoutTimeUnit, int rebroadcastCount) {

        PublicKey peerKey = generateRSAPublicKey(peerPublicKeyData);

        Buffer payloadMessage = new Buffer();

        payloadMessage.appendInt(EVAPMessage.PROTOCOL_VERSION);

        // Ensure the message type is added at the beginning of the payload
        payloadMessage.appendInt(msgType); // This essentially means that we want to pin some data on IPFS

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

        // This is so we can verify the message! Todo this might not be the best idea or really secure at all.
        payloadMessage.appendInt(payloadPeer.length());
        payloadMessage.appendString(payloadPeer);

        // TODO handle acknowledgement data here.

        boolean requiresAck = ackHandler != null;

        if (requiresAck) {
            payloadMessage.appendByte((byte) 10); // This means we must send an ack message back.
        }

        Buffer encryptedPayload = new Buffer();

        Buffer payloadData = CryptoUtil.encryptRSA(peerKey, payloadMessage);

        encryptedPayload.appendInt(payloadData.length());
        encryptedPayload.appendBuffer(payloadData);

        Buffer hashData = new Buffer();
        hashData.appendBytes(peerPublicKeyData);
        hashData.appendBuffer(payloadMessage);
        hashData.appendBuffer(message);

        String msgHash = CryptoUtils.calculateSHA512(hashData.getBytes());

        // This helps us ensure the message wasn't tampered with.
        Buffer newBuffer = new Buffer();
        newBuffer.appendInt(msgHash.length());
        newBuffer.appendString(msgHash);
        newBuffer.appendBuffer(encryptedPayload);

        Buffer messageToEncrypt = new Buffer();

        messageToEncrypt.appendInt(message.length());
        messageToEncrypt.appendBuffer(message);

        // Let's construct the acknowledgement message
        if (requiresAck) {

            Buffer ackReplyMessage = new Buffer();
            ackReplyMessage.appendInt(msgHash.length());
            ackReplyMessage.appendString(msgHash);

            BiConsumer<String, Buffer> messageConsumer = (peerAddress, finalAckMessage) -> {

                Buffer ackReplyData = new Buffer();

                ackReplyData.appendInt(peerAddress.length());
                ackReplyData.appendString(peerAddress);

                ackReplyData.appendInt(finalAckMessage.length());
                ackReplyData.appendBuffer(finalAckMessage);

                messageToEncrypt.appendInt(EVAPMessage.PayloadType.ACK.code);
                messageToEncrypt.appendInt(ackReplyData.length());
                messageToEncrypt.appendBuffer(ackReplyData);

                // Let's handle the ack timeout!
                if(ackTimeout > 0 && ackTimeoutTimeUnit != null){
                    long timeoutTimer = localAsync.setPeriodic(ackTimeoutTimeUnit.toMillis(ackTimeout), new Handler<Long>() {
                        int retryCount = 0;
                        @Override
                        public void handle(Long event) {
                            retryCount++;
                            if(retryCount > rebroadcastCount){
                                localAsync.cancelTimer(event);
                                ackResponseHandlers.remove(msgHash);
                                localAsync.runOnContext(event1 -> ackHandler.handle(new DefaultFutureResult<>(new Exception("Acknowledgement not received before timeout! Maximum amount of message rebroadcasts reached."))));
                                return;
                            }
                            localAsync.runOnContext(event1 -> ackHandler.handle(new DefaultFutureResult<>(new Exception("Acknowledgement not received before timeout! Rebroadcasting message..."))));
                        }
                    });
                    ackResponseHandlers.put(msgHash, event -> {
                        localAsync.cancelTimer(timeoutTimer);
                        localAsync.runOnContext(ignored -> ackHandler.handle(event));
                    });
                } else {
                    ackResponseHandlers.put(msgHash, ackHandler);
                }
            };

            if(multiLayerSupportEnabled){
                // This will go ahead and ensure that the ack message that is sent, is always a multi-layered message.
                constructMultiLayerMessage(publicKey.getEncoded(),
                        EVAPMessage.PayloadType.ACK.code, ackReplyMessage, messageConsumer);
            } else {
                // This is the message that we should receive back.
                constructPeerMessage(payloadPeer, publicKey.getEncoded(),
                        EVAPMessage.PayloadType.ACK.code, ackReplyMessage, messageConsumer);
            }
        }

        // Encrypt the actual message data.
        Buffer encryptedMessage = CryptoUtil.encrypt(secretKey, messageToEncrypt);

        newBuffer.appendInt(encryptedMessage.length());
        newBuffer.appendBuffer(encryptedMessage);

        Buffer finalMessage = new Buffer();

        finalMessage.appendInt(newBuffer.length());
        finalMessage.appendBuffer(newBuffer);

        // We must ensure that the data is signed.
        /*Buffer signedData = new Buffer();

        signedData.appendBuffer(signRSA(newBuffer, localService.privateKey));

        finalMessage.appendInt(signedData.length());
        finalMessage.appendBuffer(signedData);*/

        consumer.accept(calculateSHA1(peerPublicKeyData), finalMessage);

    }

    /**
     * This will construct an encrypted payload destined to route through multiple peers. It does this by passing it through
     * trusted peers, and their trusted peers. This provides anonymity when it comes to broadcasting messages to peers. The receiving peer
     * will never know the sending peer.
     *
     * @param finalPeerPublicKeyData
     * @param msgType
     * @param message
     * @param consumer
     */
    private void constructMultiLayerMessage(byte[] finalPeerPublicKeyData, int msgType, Buffer message, BiConsumer<String, Buffer> consumer){

        // TODO develop messages that are routed through many routes. This ensures a message lives.

        if(trustedPeers.size() == 0 || localPeerTable.size() == 0){
            logger.error("It looks like there aren't any relay peers available!");
            return;
        }

        // Note: this will construct a layered message meant to pass through multiple peers. These peers are
        // trusted relay peers and generally they must trust you to relay the messages.

        // We need to ensure we create the initial message.
        Buffer lastMessage = new Buffer();

        byte[] lastPeer = null;

        List<String> nTrustedRelayPeers = new LinkedList<>(trustedPeers);

        Collections.shuffle(nTrustedRelayPeers, CryptoUtil.getSecureRandom());

        String[] trustedPeers = nTrustedRelayPeers.toArray(new String[this.trustedPeers.size()]);

        for (int i = 0; i < trustedPeers.length; i++) {
            String trustedRelayPeer = trustedPeers[i];
            byte[] peerKeyData = getPublicKey(trustedRelayPeer);

            String[] peerAddress = new String[1];

            Buffer finalLastMessage = new Buffer();

            if(lastMessage.length() == 0){
                constructPeerMessage(trustedRelayPeer, finalPeerPublicKeyData, msgType, message, (peerAddr, buffer) -> {
                    peerAddress[0] = peerAddr;

                    finalLastMessage.appendBuffer(buffer);
                });
            } else {
                peerAddress[0] = calculateSHA1(lastPeer);
                finalLastMessage.appendBuffer(lastMessage);
            }

            Buffer relayMessage = new Buffer();

            relayMessage.appendInt(peerAddress[0].length());
            relayMessage.appendString(peerAddress[0]);

            relayMessage.appendInt(finalLastMessage.length());
            relayMessage.appendBuffer(finalLastMessage);

            lastMessage = new Buffer();

            Buffer actualLastMessage = lastMessage;
            constructPeerMessage((i == trustedRelayPeer.length() - 1) ? peerKeyHash : trustedRelayPeer, peerKeyData, EVAPMessage.PayloadType.MESSAGE_RELAY.code, relayMessage, (ignored, buffer) -> actualLastMessage.appendBuffer(buffer));

            lastPeer = peerKeyData;
        }

        consumer.accept(calculateSHA1(lastPeer), lastMessage);
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
