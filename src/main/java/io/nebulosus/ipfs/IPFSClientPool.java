package io.nebulosus.ipfs;

import io.ipfs.api.IPFS;

import java.util.ArrayList;
import java.util.List;

public class IPFSClientPool {

    private List<IPFS> ipfsList = new ArrayList<>();

    public IPFSClientPool(){
        this(5);
    }

    public IPFSClientPool(int initialSize){
        while (ipfsList.size() < initialSize){
            addInstance();
        }
    }

    private void addInstance(){
        IPFS instance = new IPFS("/ip4/127.0.0.1/tcp/5001");
        ipfsList.add(instance);
    }

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

    public void release(IPFS instance){
        ipfsList.add(instance);
    }

}
