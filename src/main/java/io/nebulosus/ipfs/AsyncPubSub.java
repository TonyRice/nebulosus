package io.nebulosus.ipfs;

import io.ipfs.api.IPFS;
import io.jsync.Async;
import io.jsync.AsyncFactory;
import io.jsync.Handler;
import io.jsync.app.ClusterApp;
import io.jsync.app.core.Logger;
import io.jsync.json.JsonObject;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * This is a simple class that allows you to interact with IPFS pubsub in an asynchronous manner.
 */
public class AsyncPubSub {

    private Logger logger = null;

    private Map<String, Supplier<Object>> topicSuppliers = new ConcurrentHashMap<>();
    private Map<String, Handler<JsonObject>> handlerMap = new ConcurrentHashMap<>();

    private IPFS ipfs = null;
    private Async async = null;

    /**
     * Create a new AsyncPubSub class with the specified
     * IPFS instance.
     *
     * @param ipfs the IPFS instance you wish to use
     */
    public AsyncPubSub(IPFS ipfs){
        this(ipfs, AsyncFactory.newAsync());
    }

    /**
     * Create a new AsyncPubSub class with a specified
     * IPFS, and Async instance.
     *
     * @param ipfs the IPFS instance you wish to use
     * @param async the Async instance you wish to use
     */
    public AsyncPubSub(IPFS ipfs, Async async){

        try {
            logger = ClusterApp.activeInstance().cluster().logger();
        } catch (Exception ignored){
            logger = new Logger();
        }

        this.ipfs = ipfs;
        this.async = async;

        // TODO check if this is resource intensive or not.
        async.setPeriodic(1, event -> {
            try {

                for (Map.Entry<String, Supplier<Object>> entry : topicSuppliers.entrySet()) {
                    String topic = entry.getKey();
                    Supplier<Object> supplier = entry.getValue();

                    async.executeBlocking(() -> {
                        try {
                            Object result = supplier.get();
                            Map mapResult = (Map) result;
                            if(mapResult.size() > 0){
                                return new JsonObject(mapResult);
                            }
                        } catch (Exception ignored){
                        }
                        return null;
                    }, event12 -> {
                        JsonObject result = event12.result();
                        if(result != null){
                            Handler<JsonObject> handler = handlerMap.get(topic);
                            if(handler != null){
                                async.runOnContext(event1 -> handler.handle(result));
                            }
                        }
                    });
                }
            } catch (Exception e){
                logger.error("processing error", e);
                async.cancelTimer(event);
            }
        });
    }

    /**
     * Publish data to the specified IPFS topic.
     *
     * @param topic the topic
     * @param data the data
     *
     * @return an instance of this
     */
    public AsyncPubSub pub(String topic, String data){
        async.runOnContext(event -> {
            try {
                ipfs.pubsub.pub(topic, data);
            } catch (IOException e) {
                logger.error("Error calling pub", e);
            }
        });
        return this;
    }

    /**
     * Handle data for the specified topic.
     *
     * @param topic the topic
     * @param handler the handler
     *
     * @return an instance of this
     */
    public AsyncPubSub sub(String topic, Handler<JsonObject> handler){
        async.runOnContext(event -> {
            if(!topicSuppliers.containsKey(topic)){
                try {
                    topicSuppliers.put(topic, ipfs.pubsub.sub(topic));
                } catch (IOException e) {
                    logger.error("Error calling sub", e);
                }
            }

            handlerMap.put(topic, handler);
        });
        return this;
    }

    /**
     * Allows you to easily stop receiving data for a specified topic.
     *
     * @param topic the topic
     *
     * @return an instance of this
     */
    public AsyncPubSub unsub(String topic){
        async.runOnContext(event -> {
            if(topicSuppliers.containsKey(topic)){
                topicSuppliers.remove(topic);
            }
            if(handlerMap.containsKey(topic)){
                handlerMap.remove(topic);
            }
        });
        return this;
    }
}
