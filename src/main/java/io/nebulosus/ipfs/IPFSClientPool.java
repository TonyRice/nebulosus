package io.nebulosus.ipfs;

import io.ipfs.api.IPFS;

import java.util.ArrayList;
import java.util.List;

/***
 * This simply allows us to create a pool of IPFS clients. This may eventually be deprecated.
 */
public class IPFSClientPool {

    final public static String DEFAULT_ADDRESS = "/ip4/127.0.0.1/tcp/5001";

    private List<IPFS> ipfsList = new ArrayList<>();

    /**
     * By default a pool is initialized with 5 clients.
     *
     * @param address the address you wish to connect the client to
     **/
    public IPFSClientPool(String address){
        this(5, address);
    }

    /**
     * Initialize the pool with a specific number of clients.
     *
     * @param initialSize number of clients you want to initialize
     * @param address the address you wish to connect the client to
     */
    public IPFSClientPool(int initialSize, String address){
        while (ipfsList.size() < initialSize){
            addInstance(address);
        }
    }

    private void addInstance(String address){
        IPFS instance = new IPFS(address);
        ipfsList.add(instance);
    }

    /**
     * Retrieve an IPFSClient from the pool.
     *
     * @return a new IPFSClient from the pool. If there isn't any available it will wait for one.
     * This is dangerous lol
     */
    public IPFS get(){
        try {
            if(ipfsList.size() > 0){
                return ipfsList.remove(ipfsList.size() -1);
            }
        } catch (Exception ignored){
        }
        while(!(ipfsList.size() > 0)){
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                break;
            }
        }
        return get();
    }

    /**
     * We need to release the IPFSClient back into the pool to safely use it.
     *
     * @param instance
     */
    public void release(IPFS instance){
        ipfsList.add(instance);
    }

}
