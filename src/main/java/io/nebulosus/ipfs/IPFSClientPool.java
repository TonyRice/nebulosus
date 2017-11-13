package io.nebulosus.ipfs;

import io.ipfs.api.IPFS;
import io.jsync.Async;
import io.jsync.AsyncFactory;
import io.jsync.app.ClusterApp;
import io.jsync.app.core.Logger;
import io.jsync.impl.Windows;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/***
 * This simply allows us to create a pool of IPFS clients. It also has the ability to start IPFS locally.
 */
public class IPFSClientPool {

    final public static String DEFAULT_ADDRESS = "/ip4/127.0.0.1/tcp/5001";

    private static IPFSClientPool DEFAULT_INSTANCE = null;

    public static IPFSClientPool defaultInstance(){
        if(DEFAULT_INSTANCE == null){
            DEFAULT_INSTANCE = new IPFSClientPool(5);
        }
        return DEFAULT_INSTANCE;
    }

    private Async async = null;
    private Logger logger = null;

    private List<IPFS> ipfsList = new ArrayList<>();

    private Thread ipfsDaemonThread = null;

    /**
     * By default a pool is initialized with 5 clients with the default address.
     *
     **/
    public IPFSClientPool(){
        this(5, DEFAULT_ADDRESS);
    }

    /**
     * By default a pool is initialized with 5 clients.
     *
     * @param address the address you wish to connect the client to
     **/
    public IPFSClientPool(String address){
        this(5, address);
    }

    public IPFSClientPool(int initialSize){
        this(initialSize, DEFAULT_ADDRESS);
    }

    /**
     * Initialize the pool with a specific number of clients.
     *
     * @param initialSize number of clients you want to initialize
     * @param address the address you wish to connect the client to
     */
    public IPFSClientPool(int initialSize, String address){
        try {
            async = ClusterApp.activeInstance().cluster().localAsync();
            logger = ClusterApp.activeInstance().cluster().logger();
        } catch (Exception ignored){
            async = AsyncFactory.newAsync();
            logger = new Logger();
        }

        if(address.equals(DEFAULT_ADDRESS)){
            checkDefaultIPFS();
        }

        while (ipfsList.size() < initialSize){
            addInstance(address);
        }
    }

    private void checkDefaultIPFS(){
        logger.info("Verifying IPFS API connection to \"" + DEFAULT_ADDRESS + "\".");
        try {
            IPFS ipfs = new IPFS(DEFAULT_ADDRESS);
            ipfs.version();
            logger.info("Connection to \"" + DEFAULT_ADDRESS + "\" succeeded!");
        } catch (Exception e){
            logger.warn("Connection to \"" + DEFAULT_ADDRESS + "\" failed.");
            CountDownLatch waitLatch = new CountDownLatch(1);
            ipfsDaemonThread = new Thread(() -> {
                try {
                    logger.info("Attempting to start the IPFS daemon locally.");
                    String defaultCommand = "ipfs";

                    Path localIPFSPath;
                    if(Windows.isWindows()){
                        localIPFSPath = Paths.get("ipfs.exe");
                    } else {
                        localIPFSPath = Paths.get("ipfs");
                    }
                    if(Files.exists(localIPFSPath)){
                        defaultCommand = localIPFSPath.toAbsolutePath().toString();
                        logger.info("Using the IPFS binary stored at \"" + defaultCommand + "\".");
                    }

                    // Let's attempt to ensure IPFS is initialized.
                    try {
                        new ProcessBuilder(defaultCommand, "init").start().waitFor();
                    } catch (Exception ignored){
                    }

                    ProcessBuilder processBuilder = new ProcessBuilder(defaultCommand, "daemon", "--enable-pubsub-experiment");

                    processBuilder.redirectInput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.PIPE);

                    Process process = processBuilder.start();

                    InputStream stdout = process.getInputStream();
                    BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(stdout));

                    logger.info("Attempting to detect the startup of the IPFS Daemon.");

                    async.setPeriodic(25, event -> {
                        try {
                            String line = stdoutReader.readLine();
                            if(line != null && line.equals("Daemon is ready")){
                                logger.info("The IPFS daemon is ready!");
                                async.cancelTimer(event);
                                waitLatch.countDown();
                            }
                        } catch (IOException ignored) {
                            async.cancelTimer(event);
                        }
                    });

                    process.waitFor();

                    if(waitLatch.getCount() > 0){
                        logger.error("It looks like the IPFS daemon could not be started!");

                        waitLatch.countDown();
                    }
                } catch (IOException | InterruptedException e12) {
                    logger.error("IPFS daemon error", e12);
                }
            });

            // we don't want to keep the process open
            ipfsDaemonThread.setDaemon(true);
            ipfsDaemonThread.start();

            try {
                waitLatch.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e1) {
                logger.info("The IPFS client pool may have not started successfully.");
            }
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

        throw new RuntimeException("It looks like the IPFSClientPool is empty!");
    }

    /**
     * We need to release the IPFSClient back into the pool to safely use it.
     *
     * @param instance
     */
    public IPFSClientPool release(IPFS instance){
        ipfsList.add(instance);
        return this;
    }

}
