package io.nebulosus;

import com.hazelcast.config.EvictionPolicy;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MapStoreConfig;
import com.hazelcast.core.IMap;
import com.hazelcast.core.MapLoader;
import com.hazelcast.core.MapStoreFactory;
import com.hazelcast.map.merge.LatestUpdateMapMergePolicy;
import io.jsync.Handler;
import io.jsync.app.ClusterApp;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.Logger;
import io.jsync.app.core.persistence.impl.DummyDataPersistor;
import io.jsync.app.core.service.ClusterService;
import io.jsync.json.JsonObject;
import io.jsync.logging.impl.LoggerFactory;
import io.jsync.utils.Token;
import io.nebulosus.evap.EVAPPeerService;
import io.nebulosus.ipfs.IPFSCryptoPersistor;
import io.nebulosus.sockjs.SockJSAPIService;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

public class NebulosusServer extends ClusterApp {

    static {
        System.setProperty("java.net.preferIPv4Stack", "true");

        System.setProperty("hazelcast.phone.home.enabled", "false");
        System.setProperty("hazelcast.socket.bind.any", "false");
        System.setProperty("async.pool.eventloop.size", String.valueOf(Runtime.getRuntime().availableProcessors() * 2));
        System.setProperty("async.pool.worker.size", String.valueOf(Runtime.getRuntime().availableProcessors() * 4));

        System.setProperty("org.apache.sshd.security.provider.BC.enabled", "false");

        if(System.getProperty("java.util.logging.config.file") == null){
            System.setProperty("java.util.logging.config.file", "default_logging.properties");
            System.setProperty(LoggerFactory.LOGGER_PROPERTIES_FILE, "default_logging.properties");
        } else {
            System.setProperty(LoggerFactory.LOGGER_PROPERTIES_FILE, System.getProperty("java.util.logging.config.file"));
        }
    }

    @Override
    protected void prepareConfig(Config config) {
        JsonObject jsonConfig = config.rawConfig();
        JsonObject clusterConfig = jsonConfig.getObject("cluster" , new JsonObject());
        clusterConfig.putString("data_persistor", DummyDataPersistor.class.getCanonicalName());
        clusterConfig.putString("role", "node");
        jsonConfig.putObject("cluster", clusterConfig);
    }

    @Override
    protected void prepareCluster(Cluster cluster) {

        Config config = cluster.config();

        JsonObject jsonConfig = config.rawConfig();

        Logger logger = cluster.logger();

        logger.info("Preparing to start NebulosusServer...");

        logger.info("Setting up Hazelcast IMap configuration for \"nbdata\"...");

        // -- IMPORTANT --
        // IMPORTANT We need to update the hazelcast configuration
        MapConfig nbDataMapConfig = new MapConfig();
        nbDataMapConfig.setName("nbdata");
        nbDataMapConfig.setInMemoryFormat(InMemoryFormat.BINARY);
        nbDataMapConfig.setBackupCount(0);
        nbDataMapConfig.setAsyncBackupCount(1);
        nbDataMapConfig.setEvictionPolicy(EvictionPolicy.NONE);
        nbDataMapConfig.setMergePolicy(LatestUpdateMapMergePolicy.class.getName());

        MapStoreConfig mapStoreConfig = new MapStoreConfig();
        mapStoreConfig.setInitialLoadMode(MapStoreConfig.InitialLoadMode.EAGER);
        mapStoreConfig.setWriteDelaySeconds(0);
        mapStoreConfig.setEnabled(true);

        mapStoreConfig.setFactoryImplementation(new MapStoreFactory() {
            @Override
            public MapLoader newMapStore(String mapName, Properties properties) {
                return new IPFSCryptoPersistor();
            }
        });

        nbDataMapConfig.setMapStoreConfig(mapStoreConfig);

        cluster.manager().addConfigHandler(hazelcastConfig -> {
            logger.info("Storing latest Hazelcast IMap configuration for \"nbdata\"...");
            hazelcastConfig.addMapConfig(nbDataMapConfig);
        });
        nbDataMapConfig.setMapStoreConfig(mapStoreConfig);
        // -- IMPORTANT --

        // This just ensures that the "nbdata" map is loaded.
        cluster.addService(new ClusterService() {
            private boolean started = false;

            @Override
            public void start(Cluster owner) {
                started = true;

                Logger logger = owner.logger();

                logger.info("Ensuring the map \"nbdata\" can be preloaded.");

                // This represents the data we store in this nebulosus keyvalue store
                IMap<String, String> nbdata = owner.data().getMap("nbdata",false);

                logger.info("Finished loading the map \"nbdata\" with " + nbdata.size() + " keys.");

                nbdata.put("hello", "world");

                assert nbdata.get("hello").equals("world");

            }

            @Override
            public void stop() {
                started = false;
            }

            @Override
            public boolean running() {
                return started;
            }

            @Override
            public String name() {
                return "PreLoadService";
            }
        });

        boolean enableSockJS = jsonConfig.getBoolean("enable_sockjs", true);
        if(enableSockJS){
            cluster.addService(new SockJSAPIService());
        }

        EVAPPeerService evapPeerService = new EVAPPeerService();

        cluster.addService(evapPeerService);
    }

    public static void main(String[] args){
        List<String> arguments = new LinkedList<>(Arrays.asList(args));
        arguments.add("--join");
        ClusterApp.initialize(new NebulosusServer(), arguments.toArray(new String[arguments.size()]));
    }
}
